import demistomock as demisto
from CommonServerPython import *


class Client(BaseClient):
    def __init__(self, server_url, verify, proxy, headers, auth):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers, auth=auth)

    def downloadexportcsv_request(self, exportID):
        headers = self._headers
        headers['Accept'] = 'application/gzip'

        response = self._http_request('get', f'findings/export/{exportID}', headers=headers)

        return response

    def exportallvulnerabilities_request(self, exportrequest_format):
        data = assign_params(format=exportrequest_format)
        headers = self._headers

        response = self._http_request('post', 'findings/export', json_data=data, headers=headers)

        return response

    def getapresignedurlforscannerscript_request(self, os, version):
        params = assign_params(os=os, version=version)
        headers = self._headers

        response = self._http_request('get', 'scanners/url', params=params, headers=headers)

        return response

    def getexportprogress_request(self, exportID):
        headers = self._headers

        response = self._http_request('get', f'findings/export/status/{exportID}', headers=headers)

        return response

    def import_control_request(self, importcontrolrequest_externalid, importcontrolrequest_instanceid, importcontrolrequest_product,
                               importcontrolrequest_serializedfeatures, importcontrolrequest_serializedparams, importcontrolrequest_type):
        data = assign_params(externalID=importcontrolrequest_externalid, instanceID=importcontrolrequest_instanceid, product=importcontrolrequest_product,
                             serializedFeatures=importcontrolrequest_serializedfeatures, serializedParams=importcontrolrequest_serializedparams, type=importcontrolrequest_type)
        headers = self._headers

        response = self._http_request('post', 'controls', json_data=data, headers=headers)

        return response

    def import_instance_request(self, importinstancerequest_id, importinstancerequest_name,
                                importinstancerequest_os, importinstancerequest_serializedparams, importinstancerequest_tenantcontext):
        data = assign_params(id=importinstancerequest_id, name=importinstancerequest_name, os=importinstancerequest_os,
                             serializedParams=importinstancerequest_serializedparams, tenantContext=importinstancerequest_tenantcontext)
        headers = self._headers

        response = self._http_request('post', 'instances', json_data=data, headers=headers)

        return response

    def investigateavulnerability_request(self, findingID):
        headers = self._headers

        response = self._http_request('get', f'findings/{findingID}', headers=headers)

        return response

    def mitigation_performed_request(self, mitigationstatus_external_ticket_id,
                                     mitigationstatus_external_ticket_url, mitigationstatus_id, mitigationstatus_state):
        data = assign_params(external_ticket_id=mitigationstatus_external_ticket_id,
                             external_ticket_url=mitigationstatus_external_ticket_url, id=mitigationstatus_id, state=mitigationstatus_state)
        headers = self._headers

        response = self._http_request('post', 'mitigations/performed', json_data=data, headers=headers)

        return response

    def mitigations_export_request(self, filter_):
        params = assign_params(filter=filter_)
        headers = self._headers

        response = self._http_request('get', 'mitigations', params=params, headers=headers)

        return response

    def mitigations_performed_request(self, mitigationsstatus_mitigation_id,
                                      mitigationsstatus_mitigation_ids, mitigationsstatus_state):
        data = assign_params(mitigation_id=mitigationsstatus_mitigation_id,
                             mitigation_ids=mitigationsstatus_mitigation_ids, state=mitigationsstatus_state)
        headers = self._headers

        response = self._http_request('post', 'mitigations', json_data=data, headers=headers)

        return response

    def queryvulnerabilities_request(self, offset, count, query):
        params = assign_params(offset=offset, count=count, query=query)
        headers = self._headers

        response = self._http_request('post', 'findings', params=params, headers=headers)

        return response

    def upload_scan_request(self, scanuploadrequestjson_instancecontext,
                            scanuploadrequestjson_scancontext, scanuploadrequestjson_tenantcontext):
        data = assign_params(instanceContext=scanuploadrequestjson_instancecontext,
                             scanContext=scanuploadrequestjson_scancontext, tenantContext=scanuploadrequestjson_tenantcontext)
        headers = self._headers

        response = self._http_request('post', 'scans', json_data=data, headers=headers)

        return response


def downloadexportcsv_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    exportID = str(args.get('exportID', ''))

    response = client.downloadexportcsv_request(exportID)
    command_results = CommandResults(
        outputs_prefix='Zafran',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def exportallvulnerabilities_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    exportrequest_format = str(args.get('exportrequest_format', 'csv.gz'))

    response = client.exportallvulnerabilities_request(exportrequest_format)
    command_results = CommandResults(
        outputs_prefix='Zafran',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def getapresignedurlforscannerscript_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    os = str(args.get('os', ''))
    version = str(args.get('version', ''))

    response = client.getapresignedurlforscannerscript_request(os, version)
    command_results = CommandResults(
        outputs_prefix='Zafran',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def getexportprogress_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    exportID = str(args.get('exportID', ''))

    response = client.getexportprogress_request(exportID)
    command_results = CommandResults(
        outputs_prefix='Zafran.ExportOperationStatusDTO',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def import_control_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    importcontrolrequest_externalid = str(args.get('importcontrolrequest_externalid', ''))
    importcontrolrequest_instanceid = str(args.get('importcontrolrequest_instanceid', ''))
    importcontrolrequest_product = str(args.get('importcontrolrequest_product', ''))
    importcontrolrequest_serializedfeatures = str(args.get('importcontrolrequest_serializedfeatures', ''))
    importcontrolrequest_serializedparams = str(args.get('importcontrolrequest_serializedparams', ''))
    importcontrolrequest_type = str(args.get('importcontrolrequest_type', ''))

    response = client.import_control_request(importcontrolrequest_externalid, importcontrolrequest_instanceid, importcontrolrequest_product,
                                             importcontrolrequest_serializedfeatures, importcontrolrequest_serializedparams, importcontrolrequest_type)
    command_results = CommandResults(
        outputs_prefix='Zafran.ImportControlResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def import_instance_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    importinstancerequest_id = str(args.get('importinstancerequest_id', ''))
    importinstancerequest_name = str(args.get('importinstancerequest_name', ''))
    importinstancerequest_os = str(args.get('importinstancerequest_os', ''))
    importinstancerequest_serializedparams = str(args.get('importinstancerequest_serializedparams', ''))
    importinstancerequest_tenantcontext_environment = str(args.get('importinstancerequest_tenantcontext_environment', ''))
    importinstancerequest_tenantcontext = assign_params(environment=importinstancerequest_tenantcontext_environment)

    response = client.import_instance_request(importinstancerequest_id, importinstancerequest_name,
                                              importinstancerequest_os, importinstancerequest_serializedparams, importinstancerequest_tenantcontext)
    command_results = CommandResults(
        outputs_prefix='Zafran.ImportInstanceResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def investigateavulnerability_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    findingID = str(args.get('findingID', ''))

    response = client.investigateavulnerability_request(findingID)
    command_results = CommandResults(
        outputs_prefix='Zafran.ClientFindingInvestigationDTO',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def mitigation_performed_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    mitigationstatus_external_ticket_id = str(args.get('mitigationstatus_external_ticket_id', ''))
    mitigationstatus_external_ticket_url = str(args.get('mitigationstatus_external_ticket_url', ''))
    mitigationstatus_id = str(args.get('mitigationstatus_id', ''))
    mitigationstatus_state = str(args.get('mitigationstatus_state', ''))

    response = client.mitigation_performed_request(
        mitigationstatus_external_ticket_id, mitigationstatus_external_ticket_url, mitigationstatus_id, mitigationstatus_state)
    command_results = CommandResults(
        outputs_prefix='Zafran.MitigationsPerformedResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def mitigations_export_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    filter_ = str(args.get('filter_', ''))

    response = client.mitigations_export_request(filter_)
    command_results = CommandResults(
        outputs_prefix='Zafran.UpstreamMitigation',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def mitigations_performed_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    mitigationsstatus_mitigation_id = str(args.get('mitigationsstatus_mitigation_id', ''))
    mitigationsstatus_mitigation_ids = argToList(args.get('mitigationsstatus_mitigation_ids', []))
    mitigationsstatus_state = str(args.get('mitigationsstatus_state', ''))

    response = client.mitigations_performed_request(
        mitigationsstatus_mitigation_id, mitigationsstatus_mitigation_ids, mitigationsstatus_state)
    command_results = CommandResults(
        outputs_prefix='Zafran.MitigationsPerformedResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def queryvulnerabilities_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    offset = int(args.get('offset', 0))
    count = int(args.get('count', 100))
    query = str(args.get('query', ''))

    response = client.queryvulnerabilities_request(offset, count, query)
    command_results = CommandResults(
        outputs_prefix='Zafran.ClientFindingDTO',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def upload_scan_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    scanuploadrequestjson_instancecontext_id = str(args.get('scanuploadrequestjson_instancecontext_id', ''))
    scanuploadrequestjson_instancecontext_os = str(args.get('scanuploadrequestjson_instancecontext_os', ''))
    scanuploadrequestjson_instancecontext = assign_params(
        id=scanuploadrequestjson_instancecontext_id, os=scanuploadrequestjson_instancecontext_os)
    scanuploadrequestjson_scancontext_deferred = argToBoolean(args.get('scanuploadrequestjson_scancontext_deferred', False))
    scanuploadrequestjson_scancontext_logs = str(args.get('scanuploadrequestjson_scancontext_logs', ''))
    scanuploadrequestjson_scancontext_scanresult = str(args.get('scanuploadrequestjson_scancontext_scanresult', ''))
    scanuploadrequestjson_scancontext_scanstatus = str(args.get('scanuploadrequestjson_scancontext_scanstatus', ''))
    scanuploadrequestjson_scancontext_scannertype = str(args.get('scanuploadrequestjson_scancontext_scannertype', ''))
    scanuploadrequestjson_scancontext = assign_params(deferred=scanuploadrequestjson_scancontext_deferred, logs=scanuploadrequestjson_scancontext_logs,
                                                      scanResult=scanuploadrequestjson_scancontext_scanresult, scanStatus=scanuploadrequestjson_scancontext_scanstatus, scannerType=scanuploadrequestjson_scancontext_scannertype)
    scanuploadrequestjson_tenantcontext_environment = str(args.get('scanuploadrequestjson_tenantcontext_environment', ''))
    scanuploadrequestjson_tenantcontext = assign_params(environment=scanuploadrequestjson_tenantcontext_environment)

    response = client.upload_scan_request(scanuploadrequestjson_instancecontext,
                                          scanuploadrequestjson_scancontext, scanuploadrequestjson_tenantcontext)
    command_results = CommandResults(
        outputs_prefix='Zafran.ScanUploadResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def test_module(client: Client) -> None:
    # Test functions here
    return_results('ok')


def main() -> None:

    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()
    url = params.get('url')
    verify_certificate: bool = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    headers = {}
    headers['Authorization'] = 'Bearer ' + params['api_key']

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        requests.packages.urllib3.disable_warnings()
        client: Client = Client(urljoin(url, '/api/v2/'), verify_certificate, proxy, headers=headers, auth=None)

        commands = {
            'zafran-downloadexportcsv': downloadexportcsv_command,
            'zafran-exportallvulnerabilities': exportallvulnerabilities_command,
            'zafran-getapresignedurlforscannerscript': getapresignedurlforscannerscript_command,
            'zafran-getexportprogress': getexportprogress_command,
            'zafran-import-control': import_control_command,
            'zafran-import-instance': import_instance_command,
            'zafran-investigateavulnerability': investigateavulnerability_command,
            'zafran-mitigation-performed': mitigation_performed_command,
            'zafran-mitigations-export': mitigations_export_command,
            'zafran-mitigations-performed': mitigations_performed_command,
            'zafran-queryvulnerabilities': queryvulnerabilities_command,
            'zafran-upload-scan': upload_scan_command,
        }

        if command == 'test-module':
            test_module(client)
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
