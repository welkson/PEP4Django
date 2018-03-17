from django.utils.deprecation import MiddlewareMixin
from django.http import HttpResponseForbidden
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import xmltodict
import requests.auth
import requests


class DjangoPEPMiddleware(MiddlewareMixin):
    def process_request(self, request):
        print "Subject.: %s" % getattr(request, 'user', None)
        print "Resource: %s" % request.path
        print "Action..: %s" % request.method

        # import ipdb
        # ipdb.set_trace()

        # deny
        # return HttpResponseForbidden()
#        return None


    def process_response(self, request, response):
        print "Middleware executed (Response)"

        return response

    def xacml_authorization_request(self, subject, action, resource):
        # disable warnings
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

        headers = {'Accept': 'application/xml',
                   'Content-Type': 'application/xml;charset=UTF-8',
                   'Authorization': 'Basic YWRtaW46YWRtaW4='}
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

        request = requests.post(url_wso2_api, headers=headers, data=data, verify=False)

        return xacml_decision_response(request)

    def xacml_decision_response(response):
        return xmltodict.parse(response.text)['Response']['Result']['Decision'] == u'Permit'
