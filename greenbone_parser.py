#!/usr/bin/env python

"""This module contains an parser for greenbone's scan XML reports.
 Also there are dataclasses as well as marshmallow schema definitons that are used by the parser."""

import re
import arrow
import xml.etree.ElementTree as et
import numpy as np
from dataclasses import dataclass, field as dc_field
from ipaddress import IPv4Network, IPv4Address, IPv4Interface
from typing import Optional, List, Dict
from marshmallow import Schema, fields as mm_fields, post_load, ValidationError


class IPv4InterfaceMarhmallowField(mm_fields.Field):
    """Marshmallow field definiton for IPv4 interfaces."""
    def _deserialize(self, value, *args, **kwargs):
        try:
            return IPv4Interface(value)
        except Exception as e:
            raise ValidationError("Not a valid IPv4Interface.") from e

    def _serialize(self, value, *args, **kwargs):
        if isinstance(value, IPv4Interface):
            return value.exploded
        else:
            return value


class IPv4NetworkMarshmallowField(mm_fields.Field):
    """Marshmallow field definiton for IPv4 networks."""
    def _deserialize(self, value, *args, **kwargs):
        try:
            return IPv4Network(value)
        except Exception as e:
            raise ValidationError("Not a valid IPv4Network.") from e

    def _serialize(self, value, *args, **kwargs):
        if isinstance(value, IPv4Network):
            return value.exploded
        else:
            return value


class IPv4AdressMarshmallowField(mm_fields.Field):
    """Marshmallow field definiton for IPv4 addresses."""
    def _deserialize(self, value, *args, **kwargs):
        try:
            return IPv4Address(value)
        except Exception as e:
            raise ValidationError("Not a valid IPv4Address.") from e

    def _serialize(self, value, *args, **kwargs):
        if isinstance(value, IPv4Address):
            return value.exploded
        else:
            return value


class ArrowMarshmallowField(mm_fields.Field):
    """Marshmallow field definiton for arrow timestamps."""
    def _deserialize(self, value, *args, **kwargs):
        try:
            return arrow.get(value)
        except Exception as e:
            raise ValidationError("Not a valid Timestamp.") from e

    def _serialize(self, value, *args, **kwargs):
        if isinstance(value, arrow.Arrow):
            return value.isoformat()
        else:
            return value


class VulnerabititySchema(Schema):
    """Marshmallow Schema for Vulnerability dataclass."""
    severity = mm_fields.Float()
    name = mm_fields.String()
    port = mm_fields.String()
    threat = mm_fields.String()
    qod = mm_fields.String()
    description = mm_fields.String()
    family = mm_fields.String()
    solution = mm_fields.String()

    @post_load
    def make_object(self, data, **kwargs):
        return Vulnerability(data['severity'],data['name'],data['port'],data['threat'],data['qod'],data['description'],data['family'],data['solution'])


@dataclass
class Vulnerability:
    """Holds the data for one vulnerability.

    data:
        severity: The CVSS of this vulnerability.
        name: A short hint about the vulnerability.
        port: The port this vulnerability was discoverd on, if known.
        thread: The thread level of this vulnerability (Low, Medium, High).
        qod: The quality of detection reported by greenbone.
        description: A longer description of the vulnerability.
        family: The broader type of vulnerability, e.g. SSL and TLS.
        solution: The solution for this vulnerability which is recommended by greenbone.
    """
    severity: float
    name: str
    port: str
    threat: str
    qod: str
    description: str
    family: str
    solution: str


class HostSchema(Schema):
    """Marshmallow Schema for Host dataclass."""
    ip = mm_fields.String()
    max_severity = mm_fields.Float()
    vulns = mm_fields.List(mm_fields.Nested(VulnerabititySchema()))

    @post_load
    def make_object(self, data, **kwargs):
        return Host(data['ip'],data['max_severity'],data['vulns'])


@dataclass
class Host:
    """Holds the vulnerability data and max CVSS for one host.

    data:
        ip: The IP address of the affected host.
        max_severity: The maximum CVSS of the discovered vulnerabilities of this host.
        vulns: A list of found vulnerabilities.
    """
    ip: str
    max_severity: float
    vulns: List[Vulnerability]


class GsmReportSchema(Schema):
    """Marshmallow Schema for GsmReport dataclass."""
    num_hosts = mm_fields.Integer()
    num_vulns = mm_fields.Integer()
    num_apps = mm_fields.Integer()

    scan_start = ArrowMarshmallowField()
    scan_end = ArrowMarshmallowField()

    task_name = mm_fields.String()

    res_hosts = mm_fields.Dict(keys=mm_fields.Str(), values=mm_fields.Nested(HostSchema()))

    @post_load
    def make_object(self, data, **kwargs):
        return GsmReport(data['num_hosts'], data['num_vulns'], data['num_apps'], data['scan_start'], data['scan_end'], data['task_name'], data['res_hosts'])


@dataclass
class GsmReport:
    """Holds all the data form a Security Scan Report.

    data:
        num_hosts: The number of discovered hosts during this scan.
        num _vulns: The number of discovered vulnerabilities during this scan.
        num_apps: The number of applications discovered during this scan.
        scan_start: An ISO 8601 timestamp of when the scan started.
        scan_end: An ISO 8601 timestamp of when the scan ended.
        task_name: The name of the scan that was performed.
        res_hosts: A dictionary (IP->Host) that holds all the hosts and therefore all the findings of this scan.
    """
    num_hosts: int
    num_vulns: int
    num_apps: int

    scan_start: arrow.Arrow
    scan_end: arrow.Arrow

    task_name: str

    res_hosts: Dict[str, Host]


def parse_XML(path: str) -> GsmReport:
    """Parses an greenbone XML export and converts it into a GsmReport dataclass.

    Args:
        path: The path to the greenbone XML file.

    Returns:
        A GsmReport dataclass that holds all important data from the greenbone report and can be serialized with marshmallow.
   """

    xtree = et.parse(path)
    xroot = xtree.getroot()

    max_severity = 0.0

    e_rep = xroot.find("report")

    num_hosts = int(e_rep.find("hosts").find("count").text)
    num_vulns = int(e_rep.find("vulns").find("count").text)
    num_apps = int(e_rep.find("apps").find("count").text)

    parse = e_rep.find("task").find("name").text
    if not isinstance(parse, str) or len(parse) < 1:
        parse = ""
    task_name = parse

    scan_start = arrow.get(e_rep.find("scan_start").text)
    scan_end = arrow.get(e_rep.find("scan_end").text)

    e_results = e_rep.find("results")

    res_hosts = {}
    for e_res in e_results:
        ip = IPv4Address(e_res.find("host").text).exploded

        parse = float(e_res.find("severity").text)
        if not np.isfinite(parse) or parse < 0:
            parse=-1.0
        severity = parse

        parse = e_res.find("name").text
        if not isinstance(parse, str) or len(parse) < 1:
            parse = ""
        name = parse

        parse = e_res.find("port").text
        if not isinstance(parse, str) or len(parse) < 1:
            parse = ""
        port = parse

        parse = e_res.find("threat").text
        if not isinstance(parse, str) or len(parse) < 1:
            parse = ""
        threat = parse

        parse = e_res.find("qod").find('value').text
        if not isinstance(parse, str) or len(parse) < 1:
            parse = ""
        qod = parse

        parse = e_res.find("description").text
        if not isinstance(parse, str) or len(parse) < 1:
            parse = ""
        description = parse

        parse = e_res.find("nvt").find("family").text
        if not isinstance(parse, str) or len(parse) < 1:
            parse = ""
        family = parse

        parse = e_res.find("nvt").find("solution").text
        if not isinstance(parse, str) or len(parse) < 1:
            parse = ""
        solution = parse

        vuln = Vulnerability(severity, name, port, threat, qod, description, family, solution)
        if ip in res_hosts:
            res_hosts[ip].vulns.append(vuln)
            if severity > max_severity:
                max_severity = severity
        else:
            res_hosts[ip] = Host(ip, severity, [vuln])

    return GsmReport(num_hosts, num_vulns, num_apps, scan_start, scan_end, task_name, res_hosts)


if __name__ == "__main__":
    # just some Testcode:
    dump_path = "/tmp/greenbone_scan_dump.json"
    data_path = "scan.xml"
    xml_data = parse_XML(data_path)

    schema = GsmReportSchema()

    dump = schema.dumps(xml_data)
    print("writing dump: to " + dump_path)
    with open(dump_path, "w") as f:
        f.write(dump)

    print("reading dumped json data")
    with open(dump_path, "r") as f:
        json_data = schema.loads(f.read())

    print("compare parsed XML vs json dump")
    print("xml_data == json_data:", xml_data == json_data)
