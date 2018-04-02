from django.utils.deprecation import MiddlewareMixin
from django.http import HttpResponseForbidden
from django.conf import settings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import xmltodict
import requests.auth
import requests
import re


class DjangoPEPMiddleware(MiddlewareMixin):
    def process_request(self, request):
        # get subject attribute from request
        req_user = getattr(request, 'user', None)
        req_resource = request.path
        req_action = request.method

        # debug
        trace_log("Subject.: %s" % req_user)
        trace_log("Resource: %s" % req_resource)
        trace_log("Action..: %s" % req_action)

        trace_log("IgnoreList: %s" % settings.DJANGOPEP_IGNORE)

        # Make a regex that matches if any of our regexes match.
        combined = "(" + ")|(".join(settings.DJANGOPEP_IGNORE) + ")"

        if not re.match(combined, req_resource):
            trace_log("Authorizing in PDP...")
            if not self.xacml_authorization_request(req_user, req_action, req_resource):
                trace_log("Authorizing in PDP... DENY")
                return HttpResponseForbidden()
            else:
                trace_log("Authorizing in PDP... PERMIT")
        else:
            trace_log("Resource ignored!")

    @staticmethod
    def xacml_decision_response(response):
        trace_log("PDP Response: %s" % response.text)
        return xmltodict.parse(response.text)['Response']['Result']['Decision'] == u'Permit'

    @staticmethod
    def xacml_authorization_request(subject, action, resource):
        # disable warnings (self-signed certificates)
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

        headers = {'Accept': 'application/xml',
                   'Content-Type': 'application/xml;charset=UTF-8',
                   'Authorization': 'Basic YWRtaW46YWRtaW4='}           # TODO: get user/pass/token from settings

        data = """
                <Request CombinedDecision="false" ReturnPolicyIdList="false" xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17">
                <Attributes Category="urn:oasis:names:tc:xacml:3.0:attribute-category:action">
                    <Attribute AttributeId="urn:oasis:names:tc:xacml:1.0:action:action-id" IncludeInResult="false">
                        <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">%s</AttributeValue>
                    </Attribute>
                </Attributes>
                <Attributes Category="urn:oasis:names:tc:xacml:3.0:attribute-category:resource">
                    <Attribute AttributeId="urn:oasis:names:tc:xacml:1.0:resource:resource-id" IncludeInResult="false">
                        <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">%s</AttributeValue>
                    </Attribute>
                </Attributes>
                <Attributes Category="urn:oasis:names:tc:xacml:1.0:subject-category:access-subject">
                    <Attribute AttributeId="urn:oasis:names:tc:xacml:1.0:subject:subject-id" IncludeInResult="false">
                        <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">%s</AttributeValue>
                    </Attribute>
                </Attributes>
                </Request>
        """ % (action, resource, subject)

        request = requests.post(settings.DJANGOPEP_URL, headers=headers, data=data, verify=False)
        return DjangoPEPMiddleware.xacml_decision_response(request)


def trace_log(msg):
    if hasattr(settings, 'DJANGOPEP_DEBUG') and settings.DJANGOPEP_DEBUG:
        print "[DjangoPEP Middleware] %s" % msg
