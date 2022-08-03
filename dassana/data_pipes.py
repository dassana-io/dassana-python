import gzip
import base64
from pyclbr import Class
from .rest import *
from .dassana_env import *
from abc import ABCMeta, abstractmethod
from datetime import datetime
from json import load, loads
from io import BufferedReader, BytesIO


class Pipe(metaclass=ABCMeta):
    def __init__(self):
        self.json_logs = []

    def exclude(self, key):
        return False

    @abstractmethod
    def push(self, content):
        pass

    def flush(self):
        flush_res = forward_logs(self.json_logs)
        self.json_logs = []
        return flush_res


class CloudTrailPipe(Pipe):
    def __init__(self):
        super().__init__()

    def exclude(self, key):
        return "digest" in key.lower()

    def push(self, content):
        with gzip.GzipFile(fileobj=BytesIO(content), mode="rb") as decompress_stream:
            log_data = load(decompress_stream)
            for record in log_data["Records"]:
                self.json_logs.append(record)


class VPCFlowPipe(Pipe):
    def __init__(self):
        super().__init__()

    def cast_field(self, k, v):
        int_fields = {
            "version",
            "srcport",
            "dstport",
            "protocol",
            "packets",
            "bytes",
            "start",
            "end",
            "tcp-flags",
            "traffic-path",
        }
        if k in int_fields:
            return int(v)
        else:
            return v

    def format_log(self, log):
        log = dict(
            (k, self.cast_field(k, v) if v != "-" else v) for k, v in log.items()
        )
        return log

    def push(self, content):
        with gzip.GzipFile(fileobj=BytesIO(content), mode="rb") as decompress_stream:
            log_data = b"".join(BufferedReader(decompress_stream))
            log_data = log_data.decode("utf-8")

            vpc_logs = log_data.splitlines()
            log_fields = vpc_logs[0].split(" ")
            vpc_log_struct = {key: None for key in log_fields}

            for i in range(1, len(vpc_logs)):
                line = 0
                log = vpc_logs[i].split(" ")

                for key in vpc_log_struct.keys():
                    vpc_log_struct[key] = log[line]
                    line += 1

                vpc_log_fmt = self.format_log(vpc_log_struct)
                self.json_logs.append(vpc_log_fmt)


class ALBPipe(Pipe):
    def __init__(self):
        super().__init__()

    def cast_field(self, k, v):
        int_fields = {
            "request_processing_time",
            "target_processing_time",
            "response_processing_time",
            "elb_status_code",
            "target_status_code",
            "received_bytes",
            "sent_bytes",
            "matched_rule_priority",
        }
        if k in int_fields:
            return int(v)
        else:
            return v

    def format_log(self, log_values):
        log_fields = [
            "type",
            "time",
            "elb",
            "client_port",
            "target_port",
            "request_processing_time",
            "target_processing_time",
            "response_processing_time",
            "elb_status_code",
            "target_status_code",
            "received_bytes",
            "sent_bytes",
            "request",
            "user_agent",
            "ssl_cipher",
            "ssl_protocol",
            "target_group_arn",
            "trace_id",
            "domain_name",
            "chosen_cert_name",
            "matched_rule_priority",
            "request_creation_time",
            "actions_executed",
            "redirect_url",
            "error_reason",
            "target_port_list",
            "target_status_code_list",
            "classification",
            "classificaton_reason",
        ]
        log = dict(zip(log_fields, log_values))
        log = dict(
            (k, self.cast_field(k, v) if v != "-" else v) for k, v in log.items()
        )
        return log

    def push(self, content):
        with gzip.GzipFile(fileobj=BytesIO(content), mode="rb") as decompress_stream:
            log_data = b"".join(BufferedReader(decompress_stream))
            log_data = log_data.decode("utf-8")

            access_logs = log_data.splitlines()

            for log in access_logs:
                merged_log = []
                log_fields = log.split(" ")
                i = 0
                while i < len(log_fields):
                    start_index = i
                    merged_string = ""
                    if log_fields[start_index][0] in ('"', "["):
                        if log_fields[start_index][-1] not in ('"', "]"):
                            i += 1
                            while log_fields[i][-1] not in ('"', "]"):
                                i += 1
                            merged_string = " ".join(log_fields[start_index:i])[1:-1]
                            i += 1
                        else:
                            merged_string = log_fields[start_index][1:-1]
                            i += 1
                    else:
                        merged_string = log_fields[start_index]
                        i += 1
                    merged_log.append(merged_string)

                alb_log_struct = self.format_log(merged_log)
                self.json_logs.append(alb_log_struct)


class WAFPipe(Pipe):
    def __init__(self):
        super().__init__()

    def push(self, content):
        with gzip.GzipFile(fileobj=BytesIO(content), mode="rb") as decompress_stream:
            log_data = b"".join(BufferedReader(decompress_stream))
            log_data = log_data.split(b"\n")
            for i in range(0, len(log_data) - 1):
                log = log_data[i].decode("utf-8")
                self.json_logs.append(log)


class S3AccessPipe(Pipe):
    def __init__(self):
        super().__init__()

    def convert_to_unix_ms(self, ts):
        ts_fmtd = ts.strip("[]").split(" ")[0]  # Remove offset
        ts_unix = datetime.strptime(ts_fmtd, "%d/%b/%Y:%H:%M:%S")
        epoch = datetime.utcfromtimestamp(0)
        return int((ts_unix - epoch).total_seconds() * 1000.0)

    def cast_field(self, k, v):
        int_fields = {
            "http_status",
            "error_code",
            "bytes_sent",
            "object_size",
            "total_time",
            "turn_around_time",
        }
        if k in int_fields:
            return int(v)
        elif k == "time":
            return self.convert_to_unix_ms(v)
        else:
            return v

    def format_log(self, log_values):
        log_fields = [
            "bucket_owner",
            "bucket",
            "time",
            "remote_ip",
            "requestor",
            "request_id",
            "operation",
            "key",
            "request_uri",
            "http_status",
            "error_code",
            "bytes_sent",
            "object_size",
            "total_time",
            "turn_around_time",
            "referer",
            "user_agent",
            "version_id",
            "host_id",
            "signature_version",
            "cipher_suite",
            "authentication_type",
            "host_header",
            "tls_version",
            "access_point_arn",
        ]
        log = dict(zip(log_fields, log_values))
        log = dict(
            (k, self.cast_field(k, v) if v != "-" else v) for k, v in log.items()
        )
        return log

    def push(self, content):
        log_data = content.decode("utf-8")
        access_logs = log_data.splitlines()

        for log in access_logs:
            merged_log = []
            log_fields = log.split(" ")
            i = 0
            while i < len(log_fields):
                start_index = i
                merged_string = ""
                if log_fields[start_index][0] in ('"', "["):
                    if log_fields[start_index][-1] not in ('"', "]"):
                        i += 1
                        while log_fields[i][-1] not in ('"', "]"):
                            i += 1
                        merged_string = " ".join(log_fields[start_index:i])[1:-1]
                        i += 1
                    else:
                        merged_string = log_fields[start_index][1:-1]
                        i += 1
                else:
                    merged_string = log_fields[start_index]
                    i += 1
                merged_log.append(merged_string)

            access_log_struct = self.format_log(merged_log)
            self.json_logs.append(access_log_struct)


class Route53QueryPipe(Pipe):
    def __init__(self):
        super().__init__()

    def push(self, content):
        with gzip.GzipFile(fileobj=BytesIO(content), mode="rb") as decompress_stream:
            log_data = b"".join(BufferedReader(decompress_stream))
            log_data = log_data.decode("utf-8")

            for log in log_data.splitlines():
                self.json_logs.append(loads(log))


class NetworkFirewallPipe(Pipe):
    def __init__(self):
        super().__init__()

    def push(self, content):
        with gzip.GzipFile(fileobj=BytesIO(content), mode="rb") as decompress_stream:
            log_data = b"".join(BufferedReader(decompress_stream))
            log_data = log_data.decode("utf-8")

            for log in log_data.splitlines():
                log = loads(log)
                log["event_timestamp"] = int(log["event_timestamp"])
                self.json_logs.append(log)


class AzureActivityPipe(Pipe):
    def __init__(self):
        super().__init__()

    def push(self, content):
        log_data = loads(content)
        for record in log_data["records"]:
            self.json_logs.append(record)


class EKSPipe(Pipe):
    def __init__(self):
        super().__init__()

    def push(self, content):
        decoded_event = base64.b64decode(content)
        decompressed_content = gzip.decompress(decoded_event)
        decompressed_content = loads(decompressed_content)
        cw_logs = decompressed_content["logEvents"]
        for log in cw_logs:
            try:
                fmt_log = loads(log["message"])
                fmt_log["timestamp"] = log["timestamp"]
            except Exception:
                fmt_log = log

            self.json_logs.append(fmt_log)


class ConfigSnapshotPipe(Pipe):
    def __init__(self):
        super().__init__()
        self.bytes_so_far = 0

    def push(self, content):
        output = content
        output["_dassana"] = {}
        output["_dassana"]["Cloud"] = "aws"
        output["_dassana"]["ResourceContainer"] = content["awsAccountId"]
        output["_dassana"]["Region"] = content["awsRegion"]
        output["_dassana"]["Service"] = content["resourceType"].split("::")[1]
        output["_dassana"]["ResourceName"] = content.get("resourceName")

        self.json_logs.append(output)

        self.bytes_so_far += len(dumps(output))
        if self.bytes_so_far >= (3000000):
            self.bytes_so_far = 0
            return True
        else:
            return False


class ConfigChangePipe(Pipe):
    def __init__(self):
        super().__init__()

    def push(self, content):
        items = content["Records"]
        for item in items:
            item["body"] = loads(item["body"])
            temp = loads(item["body"]["Message"])
            if temp["messageType"] != "ConfigurationItemChangeNotification":
                continue

            output = temp["configurationItem"]
            output["_dassana"] = {}
            output["_dassana"]["Cloud"] = "aws"
            output["_dassana"]["ResourceContainer"] = temp["configurationItem"][
                "awsAccountId"
            ]
            output["_dassana"]["Region"] = temp["configurationItem"]["awsRegion"]
            output["_dassana"]["Service"] = temp["configurationItem"][
                "resourceType"
            ].split("::")[1]
            output["_dassana"]["ResourceType"] = temp["configurationItem"][
                "resourceType"
            ]
            output["_dassana"]["ResourceID"] = temp["configurationItem"]["resourceId"]
            try:
                output["_dassana"]["ResourceName"] = temp["configurationItem"][
                    "resourceName"
                ]
            except:
                output["_dassana"]["ResourceName"] = None

            self.json_logs.append(output)


class GithubAssetPipe(Pipe):
    def __init__(self):
        super().__init__()

    def push(self, content):
        for item in content:
            output = item
            output["_dassana"] = {}
            output["_dassana"]["Cloud"] = "github"
            output["_dassana"]["ResourceContainer"] = item["owner"]["id"]
            output["_dassana"]["ResourceName"] = item["name"]
            output["_dassana"]["Region"] = "global"
            output["_dassana"]["Service"] = "git"
            output["_dassana"]["ResourceType"] = "repository"
            output["_dassana"]["ResourceID"] = item["id"]

            self.json_logs.append(output)


class PrismaPipe(Pipe):
    def __init__(self):
        super().__init__()

    def push(self, content):
        output = content
        output["_dassana"] = {}
        output["_dassana"]["Cloud"] = content["resource"]["cloudType"]
        output["_dassana"]["ResourceContainer"] = content["resource"]["accountId"]
        output["_dassana"]["ResourceName"] = content["resource"]["name"]
        output["_dassana"]["Region"] = content["resource"]["regionId"]
        output["_dassana"]["Service"] = None
        output["_dassana"]["ResourceType"] = content["resource"]["resourceType"]
        output["_dassana"]["ResourceID"] = content["resource"]["id"]

        self.json_logs.append(output)


class QualysPipe(Pipe):
    def __init__(self):
        super().__init__()

    def push(self, content):
        hosts = content["HOST_LIST_VM_DETECTION_OUTPUT"]["RESPONSE"]["HOST_LIST"][
            "HOST"
        ]
        if not isinstance(hosts, list):
            hosts = [hosts]
        for host in hosts:
            if "METADATA" in host:
                metadata = host["METADATA"]
                for item in metadata.values():
                    for attribute in item.get("ATTRIBUTE"):
                        if (
                            attribute.get("NAME")
                            == "latest/dynamic/instance-identity/document/accountId"
                        ):
                            resourceContainer = attribute.get("VALUE")
                        if (
                            attribute.get("NAME")
                            == "latest/dynamic/instance-identity/document/region"
                        ):
                            region = attribute.get("VALUE")
            if "CLOUD_RESOURCE_ID" in host:
                resourceID = host["CLOUD_RESOURCE_ID"]
            detections = host["DETECTION_LIST"]["DETECTION"]
            if not isinstance(detections, list):
                detections = [detections]
            for detection in detections:
                output = detection
                output["_dassana"] = {}
                output["_dassana"]["Cloud"] = host.get("CLOUD_PROVIDER")
                output["_dassana"]["Service"] = host.get("CLOUD_SERVICE")
                output["_dassana"]["ResourceContainer"] = resourceContainer
                output["_dassana"]["Region"] = region
                output["_dassana"]["ResourceID"] = resourceID
                if output["_dassana"]["Cloud"] == "AWS":
                    output["_dassana"]["ResourceType"] = "Instance"
                output["_dassana"]["ResourceName"] = None
                self.json_logs.append(output)


def DataPipe():
    pipe_selector = {
        "aws_cloudtrail": CloudTrailPipe,
        "aws_vpc_flow": VPCFlowPipe,
        "aws_alb": ALBPipe,
        "aws_waf": WAFPipe,
        "aws_s3_access": S3AccessPipe,
        "aws_route53_query": Route53QueryPipe,
        "aws_network_firewall": NetworkFirewallPipe,
        "azure_test": AzureActivityPipe,
        "aws_eks": EKSPipe,
        "github_assets": GithubAssetPipe,
        "prisma_cloud": PrismaPipe,
        "qualys": QualysPipe,
    }
    return pipe_selector[get_app_id()]()


def ConfigPipe(one_time=True):
    if one_time:
        return ConfigSnapshotPipe()
    else:
        return ConfigChangePipe()
