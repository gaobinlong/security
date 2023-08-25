/*
 *   Copyright OpenSearch Contributors
 *
 *   Licensed under the Apache License, Version 2.0 (the "License").
 *   You may not use this file except in compliance with the License.
 *   A copy of the License is located at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   or in the "license" file accompanying this file. This file is distributed
 *   on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *   express or implied. See the License for the specific language governing
 *   permissions and limitations under the License.
 */

import { ILegacyClusterClient, OpenSearchDashboardsRequest } from '../../../../src/core/server';
import { User } from '../auth/user';
import { TenancyConfigSettings } from '../../public/apps/configuration/panels/tenancy-config/types';
import { RoleDetail, RoleMappingDetail, TenantPrincipalType, tenantCanMatchPatterns } from './utils';
import { update } from 'lodash';

export class SecurityClient {
  constructor(private readonly esClient: ILegacyClusterClient) { }

  public async authenticate(request: OpenSearchDashboardsRequest, credentials: any): Promise<User> {
    const authHeader = Buffer.from(`${credentials.username}:${credentials.password}`).toString(
      'base64'
    );
    try {
      const esResponse = await this.esClient
        .asScoped(request)
        .callAsCurrentUser('opensearch_security.authinfo', {
          headers: {
            authorization: `Basic ${authHeader}`,
          },
        });
      return {
        username: credentials.username,
        roles: esResponse.roles,
        backendRoles: esResponse.backend_roles,
        tenants: esResponse.tenants,
        selectedTenant: esResponse.user_requested_tenant,
        credentials,
        proxyCredentials: credentials,
        tenancy_configs: esResponse.tenancy_configs,
      };
    } catch (error: any) {
      throw new Error(error.message);
    }
  }

  public async authenticateWithHeader(
    request: OpenSearchDashboardsRequest,
    headerName: string,
    headerValue: string,
    whitelistedHeadersAndValues: any = {},
    additionalAuthHeaders: any = {}
  ): Promise<User> {
    try {
      const credentials: any = {
        headerName,
        headerValue,
      };
      const headers: any = {};
      if (headerValue) {
        headers[headerName] = headerValue;
      }

      // cannot get config elasticsearch.requestHeadersWhitelist from kibana.yml file in new platfrom
      // meanwhile, do we really need to save all headers in cookie?
      const esResponse = await this.esClient
        .asScoped(request)
        .callAsCurrentUser('opensearch_security.authinfo', {
          headers,
        });
      return {
        username: esResponse.user_name,
        roles: esResponse.roles,
        backendRoles: esResponse.backend_roles,
        tenants: esResponse.teanats,
        selectedTenant: esResponse.user_requested_tenant,
        credentials,
      };
    } catch (error: any) {
      throw new Error(error.message);
    }
  }

  public async authenticateWithHeaders(
    request: OpenSearchDashboardsRequest,
    additionalAuthHeaders: any = {}
  ): Promise<User> {
    try {
      const esResponse = await this.esClient
        .asScoped(request)
        .callAsCurrentUser('opensearch_security.authinfo', {
          headers: additionalAuthHeaders,
        });
      return {
        username: esResponse.user_name,
        roles: esResponse.roles,
        backendRoles: esResponse.backend_roles,
        tenants: esResponse.tenants,
        selectedTenant: esResponse.user_requested_tenant,
      };
    } catch (error: any) {
      throw new Error(error.message);
    }
  }

  public async authinfo(request: OpenSearchDashboardsRequest, headers: any = {}) {
    try {
      return await this.esClient
        .asScoped(request)
        .callAsCurrentUser('opensearch_security.authinfo', {
          headers,
        });
    } catch (error: any) {
      throw new Error(error.message);
    }
  }

  public async dashboardsinfo(request: OpenSearchDashboardsRequest, headers: any = {}) {
    try {
      return await this.esClient
        .asScoped(request)
        .callAsCurrentUser('opensearch_security.dashboardsinfo', {
          headers,
        });
    } catch (error: any) {
      throw new Error(error.message);
    }
  }

  // Multi-tenancy APIs
  public async getMultitenancyInfo(request: OpenSearchDashboardsRequest) {
    try {
      return await this.esClient
        .asScoped(request)
        .callAsCurrentUser('opensearch_security.multitenancyinfo');
    } catch (error: any) {
      throw new Error(error.message);
    }
  }

  public async putMultitenancyConfigurations(
    request: OpenSearchDashboardsRequest,
    tenancyConfigSettings: TenancyConfigSettings
  ) {
    const body = {
      multitenancy_enabled: tenancyConfigSettings.multitenancy_enabled,
      private_tenant_enabled: tenancyConfigSettings.private_tenant_enabled,
      default_tenant: tenancyConfigSettings.default_tenant,
    };
    try {
      return await this.esClient
        .asScoped(request)
        .callAsCurrentUser('opensearch_security.tenancy_configs', {
          body,
        });
    } catch (error: any) {
      throw new Error(error.message);
    }
  }

  public async getTenantInfoWithInternalUser() {
    try {
      return this.esClient.callAsInternalUser('opensearch_security.tenantinfo');
    } catch (error: any) {
      throw new Error(error.message);
    }
  }

  public async getTenantInfo(request: OpenSearchDashboardsRequest) {
    try {
      return await this.esClient
        .asScoped(request)
        .callAsCurrentUser('opensearch_security.tenantinfo');
    } catch (error: any) {
      throw new Error(error.message);
    }
  }

  public async getSamlHeader(request: OpenSearchDashboardsRequest) {
    try {
      // response is expected to be an error
      await this.esClient.asScoped(request).callAsCurrentUser('opensearch_security.authinfo');
    } catch (error: any) {
      // the error looks like
      // wwwAuthenticateDirective:
      //   '
      //     X-Security-IdP realm="Open Distro Security"
      //     location="https://<your-auth-domain.com>/api/saml2/v1/sso?SAMLRequest=<some-encoded-string>"
      //     requestId="<request_id>"
      //   '

      if (!error.wwwAuthenticateDirective) {
        throw error;
      }

      try {
        const locationRegExp = /location="(.*?)"/;
        const requestIdRegExp = /requestId="(.*?)"/;

        const locationExecArray = locationRegExp.exec(error.wwwAuthenticateDirective);
        const requestExecArray = requestIdRegExp.exec(error.wwwAuthenticateDirective);
        if (locationExecArray && requestExecArray) {
          return {
            location: locationExecArray[1],
            requestId: requestExecArray[1],
          };
        }
        throw Error('failed parsing SAML config');
      } catch (parsingError: any) {
        console.log(parsingError);
        throw new Error(parsingError);
      }
    }
    throw new Error(`Invalid SAML configuration.`);
  }

  public async authToken(
    requestId: string | undefined,
    samlResponse: any,
    acsEndpoint: any | undefined = undefined
  ) {
    const body = {
      RequestId: requestId,
      SAMLResponse: samlResponse,
      acsEndpoint,
    };
    try {
      return await this.esClient.asScoped().callAsCurrentUser('opensearch_security.authtoken', {
        body,
      });
    } catch (error: any) {
      console.log(error);
      throw new Error('failed to get token');
    }
  }

  public async getTenantList(
    request: OpenSearchDashboardsRequest,
  ) {
    try {
      return await this.esClient.asScoped(request).callAsCurrentUser('opensearch_security.listResource', {
        resourceName: 'tenants',
      });
    } catch (error: any) {
      throw new Error('failed to get tenants');
    }
  }

  public async getWorkspace(
    request: OpenSearchDashboardsRequest,
    dashboardsIndex: string,
    workspace: string,
  ) {
    try {
      return await this.esClient.asScoped(request).callAsCurrentUser('get', {
        "index": dashboardsIndex,
        "id": 'workspace:' + workspace,
      });
    } catch (error: any) {
      if (error.statusCode === 404) {
        return error.response;
      } else {
        throw new Error('failed to get workspace, error:' + error);
      }
    }
  }

  public async getTenantPermissionMap(request: OpenSearchDashboardsRequest, tenant: string) {
    const tenantPermissionMap: Record<string, Record<string, string[]>> = {};
    try {
      const roleData = await this.esClient.asScoped(request).callAsCurrentUser('opensearch_security.getRoles');
      if (!roleData) {
        throw new Error('failed to get roles');
      }

      const roleMappingData = await this.esClient.asScoped(request).callAsCurrentUser('opensearch_security.getRoleMapping');
      if (!roleMappingData) {
        throw new Error('failed to get roleMapping');
      }
      const principalTypes = [TenantPrincipalType.Users, TenantPrincipalType.BackendRoles];
      Object.entries(roleData).forEach(entry => {
        const role = entry[0];
        const roleDetail = entry[1] as RoleDetail;
        roleDetail.tenant_permissions.forEach((tenantPermission) => {
          if (tenantCanMatchPatterns(tenant, tenantPermission.tenant_patterns)) {
            tenantPermission.allowed_actions.forEach((permission) => {
              if (!tenantPermissionMap[permission]) {
                tenantPermissionMap[permission] = {};
                principalTypes.forEach((principalType) => {
                  tenantPermissionMap[permission][principalType] = [];
                });
              }
              const roleMapping = roleMappingData[role] as RoleMappingDetail;
              principalTypes.forEach((principalType) => {
                let usersOrBackendRoles = [];
                if (principalType === TenantPrincipalType.Users) {
                  usersOrBackendRoles = roleMapping.users;
                } else {
                  usersOrBackendRoles = roleMapping.backend_roles;
                }
                tenantPermissionMap[permission][principalType] = [...tenantPermissionMap[permission][principalType],
                ...usersOrBackendRoles
                ]
              });
            });
          }
        });
      });
      return tenantPermissionMap;
    } catch (error: any) {
      throw new Error('failed to get tenant permission map, error:' + error.message);
    }
  }

  mergeWorkspacePermissions(oldPermissions: any, newPermissions: any) {
    Object.entries(newPermissions).forEach(entry => {
      const key = entry[0];
      const permission = entry[1];
      if (oldPermissions[key] && permission) {
        Object.entries(permission).forEach(entry => {
          const principalType = entry[0];
          const principals = entry[1];
          if (oldPermissions[key][principalType] && principals) {
            oldPermissions[key][principalType] = Array.from(new Set([...principals, ...oldPermissions[key][principalType]]));
          } else if (!oldPermissions[key][principalType] && principals) {
            oldPermissions[key][principalType] = principals;
          }
        });
      } else if (!oldPermissions[key] && permission) {
        oldPermissions[key] = permission;
      }
    });
    return oldPermissions;
  }

  async updateWorkspacePermission(
    request: OpenSearchDashboardsRequest,
    tenant: string,
    targetIndex: string,
    workspace: string,
    workspaceOldPermissions: any,
  ) {
    try {
      let workspacePermissions: any = {};
      const tenantPermissionMap = await this.getTenantPermissionMap(request, tenant);
      const tenantReadPermission = tenantPermissionMap['kibana_all_read'];
      if (!!tenantReadPermission) {
        workspacePermissions['library_read'] = {
          users: tenantReadPermission[TenantPrincipalType.Users],
          groups: tenantReadPermission[TenantPrincipalType.BackendRoles],
        }
      }
      const tenantWritePermission = tenantPermissionMap['kibana_all_write'];
      if (!!tenantWritePermission) {
        workspacePermissions['library_write'] = {
          users: tenantWritePermission[TenantPrincipalType.Users],
          groups: tenantWritePermission[TenantPrincipalType.BackendRoles],
        }
      }

      const newPermissions = this.mergeWorkspacePermissions(workspaceOldPermissions, workspacePermissions);
      const updateResponse = await this.esClient.asScoped(request).callAsCurrentUser('update', {
        index: targetIndex,
        id: 'workspace:' + workspace,
        body: {
          script: {
            source: 'ctx._source.permissions = params.permissions',
            lang: 'painless',
            params: {
              permissions: newPermissions,
            }
          }
        },
      });
      if (!updateResponse || updateResponse['result'] !== 'updated') {
        throw new Error('failed to update workspace permissions');
      }
    } catch (error: any) {
      throw new Error('failed to update workspace permissions, error:' + error.message);
    }
  }

  public async migrateTenant2Workspace(
    request: OpenSearchDashboardsRequest,
    tenant: string,
    sourceIndex: string,
    targetIndex: string,
    workspace: string,
    includePermissions: boolean,
    workspaceOldPermissions: any,
  ) {
    try {
      if (includePermissions) {
        await this.updateWorkspacePermission(request, tenant, targetIndex, workspace, workspaceOldPermissions);
      }

      if (sourceIndex === targetIndex) {
        const tempIndex = sourceIndex + '_temp_for_globaltenant2workspaces_migration';
        const deleteOldTempIndexResponse = await this.esClient.asScoped(request).callAsCurrentUser('indices.delete', {
          index: tempIndex,
          ignoreUnavailable: true,
        });
        if (!deleteOldTempIndexResponse || !deleteOldTempIndexResponse['acknowledged']) {
          throw new Error('Failed to delete old temp index:' + tempIndex + ' which is used to help migrating from global tenants to workspaces, ' +
            'you can delete it manually');
        }

        const reindexResponse = await this.esClient.asScoped(request).callAsCurrentUser('reindex', {
          body: {
            source: {
              index: sourceIndex,
              size: 500,
              query: {
                bool: {
                  must_not: [
                    {
                      term: {
                        type: 'workspace'
                      }
                    },
                    {
                      exists: {
                        field: 'workspaces'
                      }
                    }
                  ]
                }
              }
            },
            dest: { index: tempIndex },
          },
          refresh: true,
        });
        if (!reindexResponse || reindexResponse['failures'].length > 0) {
          throw new Error('Failed to reindex from [' + sourceIndex + '] to [' + tempIndex + '], this temporary index is used to help migrating from global tenants to workspaces, ' +
            'if the index already exsits, please delete it firstly and try again');
        }
        sourceIndex = tempIndex;
      }

      return await this.esClient.callAsInternalUser('reindex', {
        body: {
          source: { index: sourceIndex, size: 100 },
          dest: { index: targetIndex },
          script: {
            source: `
            def workspaceId = params.workspaces[0];
            def ids = ctx._id.splitOnToken(":");
            if (ids.length==2) {
              ctx._id = ids[0] + ":" + workspaceId + "-" + ids[1];
            } else {
              ctx._id += "-" + workspaceId;
            }
            ctx._source.workspaces=params.workspaces;
            def references = ctx._source.references;
            if (references!=null) {
              for (item in references) {
                if (item.id!=null) {
                  item.id = workspaceId + "-" + item.id;
                }
              }
            }
            `,
            lang: 'painless',
            params: {
              workspaces: [workspace]
            }
          },
        },
        refresh: true,
        wait_for_completion: false,
      });
    } catch (error: any) {
      throw new Error('failed to migrate tenant to workspace, error:' + error.message);
    }
  }
}
