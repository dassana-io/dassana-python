import gzip
from .rest import *
from json import dumps, load
from io import BufferedReader, BytesIO

class CloudTrailPipe():

    def __init__(self):
        self.json_logs = []
    
    def push(self, content):
        with gzip.GzipFile(fileobj=BytesIO(content), mode='rb') as decompress_stream:
            log_data = load(decompress_stream)
            for record in log_data['Records']:
                self.json_logs.append(record)
    
    def flush(self):
        # Consider returning number of docs inserted pretty-printed
        return forward_logs(self.json_logs)

class VPCFlowPipe():

    def __init__(self):
        self.json_logs = []
    
    def cast_field(self, k, v):
        int_fields = {'version', 'srcport', 'dstport', 'protocol', 'packets', 'bytes', 'start', 'end', 'tcp-flags', 'traffic-path'}
        if k in int_fields:
            return int(v)
        else:
            return v

    def format_log(self, log):
        log = dict((k, self.cast_field(k, v) if v != '-' else v) for k, v in log.items())
        return log
    
    def push(self, content):
        with gzip.GzipFile(fileobj=BytesIO(content), mode='rb') as decompress_stream:
            log_data = b"".join(BufferedReader(decompress_stream))
            log_data = log_data.decode('utf-8')

            vpc_logs = log_data.splitlines()
            log_fields = vpc_logs[0].split(' ')
            vpc_log_struct = {key: None for key in log_fields}
            
            for i in range(1, len(vpc_logs)):
                line = 0
                log = vpc_logs[i].split(' ')

                for key in vpc_log_struct.keys():
                    vpc_log_struct[key] = log[line]
                    line += 1

                vpc_log_struct = self.format_log(vpc_log_struct)
                self.json_logs.append(dumps(vpc_log_struct, default=str))
    
    def flush(self):
        # Consider returning number of docs inserted pretty-printed
        return forward_logs(self.json_logs)

class ALBPipe():

    def __init__(self):
        self.json_logs = []

    def cast_field(self, k, v):
        int_fields = {'request_processing_time', 'target_processing_time', 'response_processing_time', 'elb_status_code', 'target_status_code', 'received_bytes', 'sent_bytes', 'matched_rule_priority'}
        if k in int_fields:
            return int(v)
        else:
            return v

    def format_log(self, log_values):
        log_fields = ["type", "time", "elb", "client_port", "target_port", "request_processing_time", "target_processing_time", "response_processing_time", "elb_status_code", "target_status_code", "received_bytes", "sent_bytes", "request", "user_agent", "ssl_cipher", "ssl_protocol", "target_group_arn", "trace_id", "domain_name", "chosen_cert_name", "matched_rule_priority", "request_creation_time", "actions_executed", "redirect_url", "error_reason", "target_port_list", "target_status_code_list", "classification", "classificaton_reason"]
        log = dict(zip(log_fields, log_values))
        log = dict((k, self.cast_field(k, v) if v != '-' else v) for k, v in log.items())
        return log
    
    def push(self, content):
        with gzip.GzipFile(fileobj=BytesIO(content), mode='rb') as decompress_stream:
            log_data = b"".join(BufferedReader(decompress_stream))
            log_data = log_data.decode('utf-8')

            access_logs = log_data.splitlines()
            
            for log in access_logs:
                merged_log = []
                log_fields = log.split(' ')
                i = 0
                while i < len(log_fields):
                    start_index = i
                    merged_string = ''
                    if (log_fields[start_index][0] in ('\"', '[')): 
                        if (log_fields[start_index][-1] not in ('"', ']')):
                            i += 1
                            while log_fields[i][-1] not in ('"', ']'):
                                i += 1
                            merged_string = ' '.join(log_fields[start_index : i])[1:-1] 
                            i += 1
                        else:
                            merged_string = log_fields[start_index][1:-1]
                            i += 1
                    else:
                        merged_string = log_fields[start_index]
                        i += 1
                    merged_log.append(merged_string)

                alb_log_struct = self.format_log(merged_log)
                self.json_logs.append(dumps(alb_log_struct, default=str))
    
    def flush(self):
        # Consider returning number of docs inserted pretty-printed
        return forward_logs(self.json_logs)   

class WAFPipe():

    def __init__(self):
        self.json_logs = []
    
    def push(self, content):
        with gzip.GzipFile(fileobj=BytesIO(content), mode='rb') as decompress_stream:
            log_data = b"".join(BufferedReader(decompress_stream))
            log_data = log_data.split(b'\n')
            for i in range(0, len(log_data)-1):
                log = log_data[i].decode('utf-8')
                self.json_logs.append(log)
    
    def flush(self):
        # Consider returning number of docs inserted pretty-printed
        return forward_logs(self.json_logs)

class S3AccessPipe():

    def __init__(self):
        self.json_logs = []
    
    def cast_field(self, k, v):
        int_fields = {'http_status', 'error_code', 'bytes_sent', 'object_size', 'total_time', 'turn_around_time'}
        if k in int_fields:
            return int(v)
        else:
            return v

    def format_log(self, log_values):
        log_fields = ["bucket_owner", "bucket", "time", "remote_ip", "requestor", "request_id", "operation", "key", "request_uri", "http_status", "error_code", "bytes_sent", "object_size", "total_time", "turn_around_time", "referer", "user_agent", "version_id", "host_id", "signature_version", "cipher_suite", "authentication_type", "host_header", "tls_version", "access_point_arn"]
        log = dict(zip(log_fields, log_values))
        log = dict((k, self.cast_field(k, v) if v != '-' else v) for k, v in log.items())
        return log
    
    def push(self, content):
        log_data = content.decode('utf-8')
        access_logs = log_data.splitlines()
    
        for log in access_logs:
            merged_log = []
            log_fields = log.split(' ')
            i = 0
            while i < len(log_fields):
                start_index = i
                merged_string = ''
                if (log_fields[start_index][0] in ('\"', '[')): 
                    if (log_fields[start_index][-1] not in ('"', ']')):
                        i += 1
                        while log_fields[i][-1] not in ('"', ']'):
                            i += 1
                        merged_string = ' '.join(log_fields[start_index : i])[1:-1] 
                        i += 1
                    else:
                        merged_string = log_fields[start_index][1:-1]
                        i += 1
                else:
                    merged_string = log_fields[start_index]
                    i += 1
                merged_log.append(merged_string)

            access_log_struct = self.format_log(merged_log)
            self.json_logs.append(dumps(access_log_struct, default=str))
    
    def flush(self):
        # Consider returning number of docs inserted pretty-printed
        return forward_logs(self.json_logs)

def DataPipe(pipe):
    
    pipe_selector = {
        "Cloudtrail": CloudTrailPipe,
        "VPCFlow": VPCFlowPipe,
        "ALB": ALBPipe,
        "WAF": WAFPipe,
        "S3Access": S3AccessPipe
    }

    return pipe_selector[pipe]()



