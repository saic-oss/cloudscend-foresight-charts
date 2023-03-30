{{/*

 Licensed to the Apache Software Foundation (ASF) under one or more
 contributor license agreements.  See the NOTICE file distributed with
 this work for additional information regarding copyright ownership.
 The ASF licenses this file to You under the Apache License, Version 2.0
 (the "License"); you may not use this file except in compliance with
 the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.

*/}}
{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "superset.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "superset.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Create the name of the service account to use
*/}}
{{- define "superset.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "superset.fullname" .) .Values.serviceAccountName -}}
{{- else -}}
{{- default "default" .Values.serviceAccountName -}}
{{- end -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "superset.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}


{{- define "superset-security-manager" }}
from flask import redirect, request
from flask_appbuilder.security.manager import AUTH_OID
from superset.security import SupersetSecurityManager
from flask_oidc import OpenIDConnect
from flask_appbuilder.security.views import AuthOIDView
from flask_login import login_user
from urllib.parse import quote
from flask_appbuilder.views import ModelView, SimpleFormView, expose
from oauth2client.client import OAuth2Credentials
from oauth2client.client import OAuth2Credentials
import logging

class AuthOIDCView(AuthOIDView):
    @expose('/login/', methods=['GET', 'POST'])
    def login(self, flag=True):
        sm = self.appbuilder.sm
        oidc = sm.oid
        superset_dashboard_url = '{{ .Values.login_redirect }}'
        @self.appbuilder.sm.oid.require_login
        def handle_login():
            user = sm.auth_user_oid(oidc.user_getfield('email'))
            info = oidc.user_getinfo(['preferred_username', 'email', 'sub'])
            if user is None:
                info = oidc.user_getinfo(['preferred_username', 'given_name', 'family_name', 'email'])
                user = user = sm.add_user(info.get('preferred_username'), info.get('given_name'), info.get('family_name'),info.get('email'), sm.find_role('Gamma'))
            login_user(user, remember=False)
            return redirect(superset_dashboard_url)
        return handle_login()

    @expose('/logout/', methods=['GET', 'POST'])
    def logout(self):
        oidc = self.appbuilder.sm.oid
        oidc.logout()
        super(AuthOIDCView, self).logout()
        redirect_url = request.url_root.strip('/') + self.appbuilder.get_url_for_login
        return redirect(
            oidc.client_secrets.get('issuer') + '/protocol/openid-connect/logout?redirect_uri=' + quote(redirect_url))

class OIDCSecurityManager(SupersetSecurityManager):
    authoidview = AuthOIDCView
    def __init__(self,appbuilder):
        super(OIDCSecurityManager, self).__init__(appbuilder)
        if self.auth_type == AUTH_OID:
            self.oid = OpenIDConnect(self.appbuilder.get_app)
{{- end -}}

{{- define "superset-config" }}
import os
from cachelib.redis import RedisCache

def env(key, default=None):
    return os.getenv(key, default)

MAPBOX_API_KEY = env('MAPBOX_API_KEY', '')
CACHE_CONFIG = {
      'CACHE_TYPE': 'redis',
      'CACHE_DEFAULT_TIMEOUT': 400,
      'CACHE_KEY_PREFIX': 'superset_',
      'CACHE_REDIS_HOST': env('REDIS_HOST'),
      'CACHE_REDIS_PORT': env('REDIS_PORT'),
      'CACHE_REDIS_PASSWORD': env('REDIS_PASSWORD'),
      'CACHE_REDIS_DB': env('REDIS_DB', 1),
}
DATA_CACHE_CONFIG = CACHE_CONFIG

SQLALCHEMY_DATABASE_URI = f"postgresql+psycopg2://{env('DB_USER')}:{env('DB_PASS')}@{env('DB_HOST')}:{env('DB_PORT')}/{env('DB_NAME')}"
SQLALCHEMY_TRACK_MODIFICATIONS = True
SECRET_KEY = env('SECRET_KEY', 'thisISaSECRET_1234')

ENABLE_PROXY_FIX = True
ENABLE_TIME_ROTATE = True

OIDC_ID_TOKEN_COOKIE_SECURE = False
OIDC_REQUIRE_VERIFIED_EMAIL = False
AUTH_USER_REGISTRATION = True

# Flask-WTF flag for CSRF
WTF_CSRF_ENABLED = True
# Add endpoints that need to be exempt from CSRF protection
WTF_CSRF_EXEMPT_LIST = []
# A CSRF token that expires in 1 year
WTF_CSRF_TIME_LIMIT = 60 * 60 * 24 * 365

from superset_security_manager import OIDCSecurityManager
from flask_appbuilder.security.manager import AUTH_OID, AUTH_REMOTE_USER, AUTH_DB, AUTH_LDAP, AUTH_OAUTH
import os
CUSTOM_SECURITY_MANAGER=OIDCSecurityManager
AUTH_TYPE = AUTH_OID
OIDC_CLIENT_SECRETS = '/app/pythonpath/client_secret.json'
OIDC_ID_TOKEN_COOKIE_SECURE = False
OIDC_REQUIRE_VERIFIED_EMAIL = False
AUTH_USER_REGISTRATION = True
OIDC_OPENID_REALM: '{{ .Values.openid_realm }}'
OIDC_INTROSPECTION_AUTH_METHOD: 'client_secret_post'
AUTH_USER_REGISTRATION_ROLE = 'Gamma'

class CeleryConfig(object):
  CELERY_IMPORTS = ('superset.sql_lab', )
  CELERY_ANNOTATIONS = {'tasks.add': {'rate_limit': '10/s'}}
{{- if .Values.supersetNode.connections.redis_password }}
  BROKER_URL = f"redis://:{env('REDIS_PASSWORD')}@{env('REDIS_HOST')}:{env('REDIS_PORT')}/0"
  CELERY_RESULT_BACKEND = f"redis://:{env('REDIS_PASSWORD')}@{env('REDIS_HOST')}:{env('REDIS_PORT')}/0"
{{- else }}
  BROKER_URL = f"redis://{env('REDIS_HOST')}:{env('REDIS_PORT')}/0"
  CELERY_RESULT_BACKEND = f"redis://{env('REDIS_HOST')}:{env('REDIS_PORT')}/0"
{{- end }}

CELERY_CONFIG = CeleryConfig
RESULTS_BACKEND = RedisCache(
      host=env('REDIS_HOST'),
{{- if .Values.supersetNode.connections.redis_password }}
      password=env('REDIS_PASSWORD'),
{{- end }}
      port=env('REDIS_PORT'),
      key_prefix='superset_results'
)

{{ if .Values.configOverrides }}
# Overrides
{{- range $key, $value := .Values.configOverrides }}
# {{ $key }}
{{ tpl $value $ }}
{{- end }}
{{- end }}
{{ if .Values.configOverridesFiles }}
# Overrides from files
{{- $files := .Files }}
{{- range $key, $value := .Values.configOverridesFiles }}
# {{ $key }}
{{ $files.Get $value }}
{{- end }}
{{- end }}

{{- end }}



{{/*
Fix Gamma Role to have the proper permissions, this json is very long - pulled directly from the export and shortened
to only use the Gamma role part
*/}}
{{- define "update_superset_roles" }}
[{"name":"Gamma","permissions":[{"permission":{"name":"can_read"},"view_menu":{"name":"SavedQuery"}},{"permission":{"name":"can_write"},"view_menu":{"name":"SavedQuery"}},{"permission":{"name":"can_read"},"view_menu":{"name":"CssTemplate"}},{"permission":{"name":"can_write"},"view_menu":{"name":"CssTemplate"}},{"permission":{"name":"can_read"},"view_menu":{"name":"ReportSchedule"}},{"permission":{"name":"can_write"},"view_menu":{"name":"ReportSchedule"}},{"permission":{"name":"can_read"},"view_menu":{"name":"Chart"}},{"permission":{"name":"can_write"},"view_menu":{"name":"Chart"}},{"permission":{"name":"can_read"},"view_menu":{"name":"Annotation"}},{"permission":{"name":"can_write"},"view_menu":{"name":"Annotation"}},{"permission":{"name":"can_read"},"view_menu":{"name":"Dataset"}},{"permission":{"name":"can_read"},"view_menu":{"name":"Dashboard"}},{"permission":{"name":"can_write"},"view_menu":{"name":"Dashboard"}},{"permission":{"name":"can_read"},"view_menu":{"name":"Database"}},{"permission":{"name":"can_read"},"view_menu":{"name":"Query"}},{"permission":{"name":"can_this_form_get"},"view_menu":{"name":"ResetMyPasswordView"}},{"permission":{"name":"can_this_form_post"},"view_menu":{"name":"ResetMyPasswordView"}},{"permission":{"name":"can_this_form_get"},"view_menu":{"name":"UserInfoEditView"}},{"permission":{"name":"can_this_form_post"},"view_menu":{"name":"UserInfoEditView"}},{"permission":{"name":"can_userinfo"},"view_menu":{"name":"UserOIDModelView"}},{"permission":{"name":"can_list"},"view_menu":{"name":"RegisterUserModelView"}},{"permission":{"name":"can_show"},"view_menu":{"name":"RegisterUserModelView"}},{"permission":{"name":"can_delete"},"view_menu":{"name":"RegisterUserModelView"}},{"permission":{"name":"can_get"},"view_menu":{"name":"OpenApi"}},{"permission":{"name":"can_show"},"view_menu":{"name":"SwaggerView"}},{"permission":{"name":"can_get"},"view_menu":{"name":"MenuApi"}},{"permission":{"name":"can_list"},"view_menu":{"name":"AsyncEventsRestApi"}},{"permission":{"name":"can_invalidate"},"view_menu":{"name":"CacheRestApi"}},{"permission":{"name":"can_export"},"view_menu":{"name":"Chart"}},{"permission":{"name":"can_write"},"view_menu":{"name":"DashboardFilterStateRestApi"}},{"permission":{"name":"can_read"},"view_menu":{"name":"DashboardFilterStateRestApi"}},{"permission":{"name":"can_export"},"view_menu":{"name":"Dashboard"}},{"permission":{"name":"can_write"},"view_menu":{"name":"ExploreFormDataRestApi"}},{"permission":{"name":"can_read"},"view_menu":{"name":"ExploreFormDataRestApi"}},{"permission":{"name":"can_delete"},"view_menu":{"name":"FilterSets"}},{"permission":{"name":"can_edit"},"view_menu":{"name":"FilterSets"}},{"permission":{"name":"can_list"},"view_menu":{"name":"FilterSets"}},{"permission":{"name":"can_add"},"view_menu":{"name":"FilterSets"}},{"permission":{"name":"can_export"},"view_menu":{"name":"SavedQuery"}},{"permission":{"name":"can_list"},"view_menu":{"name":"DynamicPlugin"}},{"permission":{"name":"can_show"},"view_menu":{"name":"DynamicPlugin"}},{"permission":{"name":"can_query"},"view_menu":{"name":"Api"}},{"permission":{"name":"can_time_range"},"view_menu":{"name":"Api"}},{"permission":{"name":"can_query_form_data"},"view_menu":{"name":"Api"}},{"permission":{"name":"can_this_form_get"},"view_menu":{"name":"CsvToDatabaseView"}},{"permission":{"name":"can_this_form_post"},"view_menu":{"name":"CsvToDatabaseView"}},{"permission":{"name":"can_this_form_get"},"view_menu":{"name":"ExcelToDatabaseView"}},{"permission":{"name":"can_this_form_post"},"view_menu":{"name":"ExcelToDatabaseView"}},{"permission":{"name":"can_this_form_get"},"view_menu":{"name":"ColumnarToDatabaseView"}},{"permission":{"name":"can_this_form_post"},"view_menu":{"name":"ColumnarToDatabaseView"}},{"permission":{"name":"can_external_metadata"},"view_menu":{"name":"Datasource"}},{"permission":{"name":"can_get"},"view_menu":{"name":"Datasource"}},{"permission":{"name":"can_external_metadata_by_name"},"view_menu":{"name":"Datasource"}},{"permission":{"name":"can_get_value"},"view_menu":{"name":"KV"}},{"permission":{"name":"can_store"},"view_menu":{"name":"KV"}},{"permission":{"name":"can_shortner"},"view_menu":{"name":"R"}},{"permission":{"name":"can_my_queries"},"view_menu":{"name":"SqlLab"}},{"permission":{"name":"can_sqllab_history"},"view_menu":{"name":"Superset"}},{"permission":{"name":"can_fave_slices"},"view_menu":{"name":"Superset"}},{"permission":{"name":"can_fave_dashboards"},"view_menu":{"name":"Superset"}},{"permission":{"name":"can_validate_sql_json"},"view_menu":{"name":"Superset"}},{"permission":{"name":"can_import_dashboards"},"view_menu":{"name":"Superset"}},{"permission":{"name":"can_log"},"view_menu":{"name":"Superset"}},{"permission":{"name":"can_save_dash"},"view_menu":{"name":"Superset"}},{"permission":{"name":"can_results"},"view_menu":{"name":"Superset"}},{"permission":{"name":"can_add_slices"},"view_menu":{"name":"Superset"}},{"permission":{"name":"can_recent_activity"},"view_menu":{"name":"Superset"}},{"permission":{"name":"can_request_access"},"view_menu":{"name":"Superset"}},{"permission":{"name":"can_annotation_json"},"view_menu":{"name":"Superset"}},{"permission":{"name":"can_available_domains"},"view_menu":{"name":"Superset"}},{"permission":{"name":"can_tables"},"view_menu":{"name":"Superset"}},{"permission":{"name":"can_search_queries"},"view_menu":{"name":"Superset"}},{"permission":{"name":"can_estimate_query_cost"},"view_menu":{"name":"Superset"}},{"permission":{"name":"can_csrf_token"},"view_menu":{"name":"Superset"}},{"permission":{"name":"can_extra_table_metadata"},"view_menu":{"name":"Superset"}},{"permission":{"name":"can_created_slices"},"view_menu":{"name":"Superset"}},{"permission":{"name":"can_profile"},"view_menu":{"name":"Superset"}},{"permission":{"name":"can_slice"},"view_menu":{"name":"Superset"}},{"permission":{"name":"can_fave_dashboards_by_username"},"view_menu":{"name":"Superset"}},{"permission":{"name":"can_select_star"},"view_menu":{"name":"Superset"}},{"permission":{"name":"can_fetch_datasource_metadata"},"view_menu":{"name":"Superset"}},{"permission":{"name":"can_publish"},"view_menu":{"name":"Superset"}},{"permission":{"name":"can_schemas"},"view_menu":{"name":"Superset"}},{"permission":{"name":"can_stop_query"},"view_menu":{"name":"Superset"}},{"permission":{"name":"can_explore_json"},"view_menu":{"name":"Superset"}},{"permission":{"name":"can_user_slices"},"view_menu":{"name":"Superset"}},{"permission":{"name":"can_schemas_access_for_file_upload"},"view_menu":{"name":"Superset"}},{"permission":{"name":"can_copy_dash"},"view_menu":{"name":"Superset"}},{"permission":{"name":"can_created_dashboards"},"view_menu":{"name":"Superset"}},{"permission":{"name":"can_csv"},"view_menu":{"name":"Superset"}},{"permission":{"name":"can_warm_up_cache"},"view_menu":{"name":"Superset"}},{"permission":{"name":"can_dashboard"},"view_menu":{"name":"Superset"}},{"permission":{"name":"can_explore"},"view_menu":{"name":"Superset"}},{"permission":{"name":"can_favstar"},"view_menu":{"name":"Superset"}},{"permission":{"name":"can_sqllab"},"view_menu":{"name":"Superset"}},{"permission":{"name":"can_queries"},"view_menu":{"name":"Superset"}},{"permission":{"name":"can_testconn"},"view_menu":{"name":"Superset"}},{"permission":{"name":"can_slice_json"},"view_menu":{"name":"Superset"}},{"permission":{"name":"can_sqllab_viz"},"view_menu":{"name":"Superset"}},{"permission":{"name":"can_sqllab_table_viz"},"view_menu":{"name":"Superset"}},{"permission":{"name":"can_filter"},"view_menu":{"name":"Superset"}},{"permission":{"name":"can_datasources"},"view_menu":{"name":"Superset"}},{"permission":{"name":"can_delete"},"view_menu":{"name":"TableSchemaView"}},{"permission":{"name":"can_post"},"view_menu":{"name":"TableSchemaView"}},{"permission":{"name":"can_expanded"},"view_menu":{"name":"TableSchemaView"}},{"permission":{"name":"can_delete"},"view_menu":{"name":"TabStateView"}},{"permission":{"name":"can_activate"},"view_menu":{"name":"TabStateView"}},{"permission":{"name":"can_migrate_query"},"view_menu":{"name":"TabStateView"}},{"permission":{"name":"can_put"},"view_menu":{"name":"TabStateView"}},{"permission":{"name":"can_delete_query"},"view_menu":{"name":"TabStateView"}},{"permission":{"name":"can_post"},"view_menu":{"name":"TabStateView"}},{"permission":{"name":"can_get"},"view_menu":{"name":"TabStateView"}},{"permission":{"name":"can_delete"},"view_menu":{"name":"TagView"}},{"permission":{"name":"can_suggestions"},"view_menu":{"name":"TagView"}},{"permission":{"name":"can_post"},"view_menu":{"name":"TagView"}},{"permission":{"name":"can_tagged_objects"},"view_menu":{"name":"TagView"}},{"permission":{"name":"can_get"},"view_menu":{"name":"TagView"}},{"permission":{"name":"can_read"},"view_menu":{"name":"SecurityRestApi"}},{"permission":{"name":"can_delete"},"view_menu":{"name":"DashboardEmailScheduleView"}},{"permission":{"name":"can_edit"},"view_menu":{"name":"DashboardEmailScheduleView"}},{"permission":{"name":"can_show"},"view_menu":{"name":"DashboardEmailScheduleView"}},{"permission":{"name":"can_list"},"view_menu":{"name":"DashboardEmailScheduleView"}},{"permission":{"name":"can_add"},"view_menu":{"name":"DashboardEmailScheduleView"}},{"permission":{"name":"can_delete"},"view_menu":{"name":"SliceEmailScheduleView"}},{"permission":{"name":"can_edit"},"view_menu":{"name":"SliceEmailScheduleView"}},{"permission":{"name":"can_show"},"view_menu":{"name":"SliceEmailScheduleView"}},{"permission":{"name":"can_list"},"view_menu":{"name":"SliceEmailScheduleView"}},{"permission":{"name":"can_add"},"view_menu":{"name":"SliceEmailScheduleView"}},{"permission":{"name":"can_delete"},"view_menu":{"name":"AlertModelView"}},{"permission":{"name":"can_edit"},"view_menu":{"name":"AlertModelView"}},{"permission":{"name":"can_show"},"view_menu":{"name":"AlertModelView"}},{"permission":{"name":"can_list"},"view_menu":{"name":"AlertModelView"}},{"permission":{"name":"can_add"},"view_menu":{"name":"AlertModelView"}},{"permission":{"name":"can_list"},"view_menu":{"name":"AlertLogModelView"}},{"permission":{"name":"can_show"},"view_menu":{"name":"AlertLogModelView"}},{"permission":{"name":"can_list"},"view_menu":{"name":"AlertObservationModelView"}},{"permission":{"name":"can_show"},"view_menu":{"name":"AlertObservationModelView"}},{"permission":{"name":"can_show"},"view_menu":{"name":"DruidDatasourceModelView"}},{"permission":{"name":"can_list"},"view_menu":{"name":"DruidDatasourceModelView"}},{"permission":{"name":"can_show"},"view_menu":{"name":"DruidClusterModelView"}},{"permission":{"name":"can_list"},"view_menu":{"name":"DruidClusterModelView"}},{"permission":{"name":"can_list"},"view_menu":{"name":"DruidMetricInlineView"}},{"permission":{"name":"can_list"},"view_menu":{"name":"DruidColumnInlineView"}},{"permission":{"name":"can_refresh_datasources"},"view_menu":{"name":"Druid"}},{"permission":{"name":"can_scan_new_datasources"},"view_menu":{"name":"Druid"}},{"permission":{"name":"menu_access"},"view_menu":{"name":"List Users"}},{"permission":{"name":"menu_access"},"view_menu":{"name":"List Roles"}},{"permission":{"name":"menu_access"},"view_menu":{"name":"User's Statistics"}},{"permission":{"name":"menu_access"},"view_menu":{"name":"Action Log"}},{"permission":{"name":"menu_access"},"view_menu":{"name":"Access requests"}},{"permission":{"name":"menu_access"},"view_menu":{"name":"Home"}},{"permission":{"name":"menu_access"},"view_menu":{"name":"Annotation Layers"}},{"permission":{"name":"menu_access"},"view_menu":{"name":"Plugins"}},{"permission":{"name":"menu_access"},"view_menu":{"name":"Import Dashboards"}},{"permission":{"name":"menu_access"},"view_menu":{"name":"DashboardEmail Schedules"}},{"permission":{"name":"menu_access"},"view_menu":{"name":"Chart Emails"}},{"permission":{"name":"menu_access"},"view_menu":{"name":"Alerts"}},{"permission":{"name":"menu_access"},"view_menu":{"name":"Alerts & Report"}},{"permission":{"name":"menu_access"},"view_menu":{"name":"Dashboards"}},{"permission":{"name":"menu_access"},"view_menu":{"name":"Charts"}},{"permission":{"name":"menu_access"},"view_menu":{"name":"SQL Editor"}},{"permission":{"name":"menu_access"},"view_menu":{"name":"Saved Queries"}},{"permission":{"name":"menu_access"},"view_menu":{"name":"Query Search"}},{"permission":{"name":"menu_access"},"view_menu":{"name":"Data"}},{"permission":{"name":"menu_access"},"view_menu":{"name":"Databases"}},{"permission":{"name":"menu_access"},"view_menu":{"name":"Datasets"}},{"permission":{"name":"menu_access"},"view_menu":{"name":"Druid Datasources"}},{"permission":{"name":"menu_access"},"view_menu":{"name":"Druid Clusters"}},{"permission":{"name":"menu_access"},"view_menu":{"name":"Scan New Datasources"}},{"permission":{"name":"all_datasource_access"},"view_menu":{"name":"all_datasource_access"}},{"permission":{"name":"all_database_access"},"view_menu":{"name":"all_database_access"}},{"permission":{"name":"can_share_dashboard"},"view_menu":{"name":"Superset"}},{"permission":{"name":"can_share_chart"},"view_menu":{"name":"Superset"}}]}]
{{- end}}




{{/*
This is the dashboard json that will plug into the image, straight from the superset export dashboard command
*/}}
{{- define "import_foresight_dashboards" }}
{
    "dashboards": [
        {
            "__Dashboard__": {
                "css": ".navbar-brand img{\n  display:none;\n}",
                "dashboard_title": "Foresight",
                "description": null,
                "json_metadata": "{\"show_native_filters\": true, \"color_scheme\": \"\", \"refresh_frequency\": 0, \"expanded_slices\": {}, \"label_colors\": {}, \"timed_refresh_immune_slices\": [], \"default_filters\": \"{}\", \"chart_configuration\": {}, \"remote_id\": 1}",
                "position_json": "{\"CHART-964PYLa7HN\":{\"children\":[],\"id\":\"CHART-964PYLa7HN\",\"meta\":{\"chartId\":2,\"height\":50,\"sliceName\":\"Cloud Readiness\",\"uuid\":\"be126096-4873-4540-af5a-e37f22134664\",\"width\":4},\"parents\":[\"ROOT_ID\",\"GRID_ID\",\"ROW-IA3ImELy1\"],\"type\":\"CHART\"},\"CHART-FVJIVilVSh\":{\"children\":[],\"id\":\"CHART-FVJIVilVSh\",\"meta\":{\"chartId\":3,\"height\":50,\"sliceName\":\"Application Health\",\"uuid\":\"a710d800-334a-4b9f-abbf-69202cc2cdcc\",\"width\":4},\"parents\":[\"ROOT_ID\",\"GRID_ID\",\"ROW-IA3ImELy1\"],\"type\":\"CHART\"},\"CHART-gxpBH0DBN7\":{\"children\":[],\"id\":\"CHART-gxpBH0DBN7\",\"meta\":{\"chartId\":1,\"height\":50,\"sliceName\":\"Technical Debt\",\"uuid\":\"6681c480-5656-41d1-9f61-1f32ab7a1d4a\",\"width\":4},\"parents\":[\"ROOT_ID\",\"GRID_ID\",\"ROW-IA3ImELy1\"],\"type\":\"CHART\"},\"DASHBOARD_VERSION_KEY\":\"v2\",\"GRID_ID\":{\"children\":[\"ROW-IA3ImELy1\"],\"id\":\"GRID_ID\",\"parents\":[\"ROOT_ID\"],\"type\":\"GRID\"},\"HEADER_ID\":{\"id\":\"HEADER_ID\",\"meta\":{\"text\":\"Foresight\"},\"type\":\"HEADER\"},\"ROOT_ID\":{\"children\":[\"GRID_ID\"],\"id\":\"ROOT_ID\",\"type\":\"ROOT\"},\"ROW-IA3ImELy1\":{\"children\":[\"CHART-gxpBH0DBN7\",\"CHART-964PYLa7HN\",\"CHART-FVJIVilVSh\"],\"id\":\"ROW-IA3ImELy1\",\"meta\":{\"0\":\"ROOT_ID\",\"background\":\"BACKGROUND_TRANSPARENT\"},\"parents\":[\"ROOT_ID\",\"GRID_ID\"],\"type\":\"ROW\"}}",
                "slices": [
                    {
                        "__Slice__": {
                            "cache_timeout": null,
                            "datasource_name": "public.technical_debt_view",
                            "datasource_type": "table",
                            "id": 1,
                            "params": "{\"adhoc_filters\": [], \"color_scheme\": \"supersetColors\", \"datasource\": \"103__table\", \"date_format\": \"smart_date\", \"extra_form_data\": {}, \"granularity_sqla\": \"Date\", \"groupby\": [\"Application Name\"], \"innerRadius\": 30, \"label_type\": \"key\", \"labels_outside\": true, \"legendOrientation\": \"top\", \"legendType\": \"scroll\", \"metric\": {\"aggregate\": \"AVG\", \"column\": {\"certification_details\": null, \"certified_by\": null, \"column_name\": \"CAST HL Tech Debt\", \"description\": null, \"expression\": null, \"filterable\": true, \"groupby\": true, \"id\": 1015, \"is_certified\": false, \"is_dttm\": false, \"python_date_format\": null, \"type\": \"DOUBLE PRECISION\", \"type_generic\": 0, \"verbose_name\": null, \"warning_markdown\": null}, \"expressionType\": \"SIMPLE\", \"hasCustomLabel\": false, \"isNew\": false, \"label\": \"AVG(CAST HL Tech Debt)\", \"optionName\": \"metric_y6abfxu5u8_ag3qm0q7oa9\", \"sqlExpression\": null}, \"number_format\": \"SMART_NUMBER\", \"outerRadius\": 70, \"row_limit\": 100, \"show_labels\": true, \"show_labels_threshold\": 5, \"show_legend\": true, \"sort_by_metric\": true, \"time_range\": \"No filter\", \"time_range_endpoints\": [\"inclusive\", \"exclusive\"], \"url_params\": {}, \"viz_type\": \"pie\", \"remote_id\": 1, \"datasource_name\": \"technical_debt_view\", \"schema\": \"public\", \"database_name\": \"{{ .Values.supersetDatabase_name }}\"}",
                            "query_context": "{\"datasource\":{\"id\":103,\"type\":\"table\"},\"force\":false,\"queries\":[{\"time_range\":\"No filter\",\"granularity\":\"Date\",\"filters\":[],\"extras\":{\"time_range_endpoints\":[\"inclusive\",\"exclusive\"],\"having\":\"\",\"having_druid\":[],\"where\":\"\"},\"applied_time_extras\":{},\"columns\":[\"Application Name\"],\"metrics\":[{\"expressionType\":\"SIMPLE\",\"column\":{\"id\":1015,\"column_name\":\"CAST HL Tech Debt\",\"verbose_name\":null,\"description\":null,\"expression\":null,\"filterable\":true,\"groupby\":true,\"is_dttm\":false,\"type\":\"DOUBLE PRECISION\",\"type_generic\":0,\"python_date_format\":null,\"is_certified\":false,\"certified_by\":null,\"certification_details\":null,\"warning_markdown\":null},\"aggregate\":\"AVG\",\"sqlExpression\":null,\"isNew\":false,\"hasCustomLabel\":false,\"label\":\"AVG(CAST HL Tech Debt)\",\"optionName\":\"metric_y6abfxu5u8_ag3qm0q7oa9\"}],\"orderby\":[[{\"expressionType\":\"SIMPLE\",\"column\":{\"id\":1015,\"column_name\":\"CAST HL Tech Debt\",\"verbose_name\":null,\"description\":null,\"expression\":null,\"filterable\":true,\"groupby\":true,\"is_dttm\":false,\"type\":\"DOUBLE PRECISION\",\"type_generic\":0,\"python_date_format\":null,\"is_certified\":false,\"certified_by\":null,\"certification_details\":null,\"warning_markdown\":null},\"aggregate\":\"AVG\",\"sqlExpression\":null,\"isNew\":false,\"hasCustomLabel\":false,\"label\":\"AVG(CAST HL Tech Debt)\",\"optionName\":\"metric_y6abfxu5u8_ag3qm0q7oa9\"},false]],\"annotation_layers\":[],\"row_limit\":100,\"timeseries_limit\":0,\"order_desc\":true,\"url_params\":{},\"custom_params\":{},\"custom_form_data\":{}}],\"form_data\":{\"viz_type\":\"pie\",\"datasource\":\"103__table\",\"url_params\":{},\"time_range_endpoints\":[\"inclusive\",\"exclusive\"],\"granularity_sqla\":\"Date\",\"time_range\":\"No filter\",\"groupby\":[\"Application Name\"],\"metric\":{\"expressionType\":\"SIMPLE\",\"column\":{\"id\":1015,\"column_name\":\"CAST HL Tech Debt\",\"verbose_name\":null,\"description\":null,\"expression\":null,\"filterable\":true,\"groupby\":true,\"is_dttm\":false,\"type\":\"DOUBLE PRECISION\",\"type_generic\":0,\"python_date_format\":null,\"is_certified\":false,\"certified_by\":null,\"certification_details\":null,\"warning_markdown\":null},\"aggregate\":\"AVG\",\"sqlExpression\":null,\"isNew\":false,\"hasCustomLabel\":false,\"label\":\"AVG(CAST HL Tech Debt)\",\"optionName\":\"metric_y6abfxu5u8_ag3qm0q7oa9\"},\"adhoc_filters\":[],\"row_limit\":100,\"sort_by_metric\":true,\"color_scheme\":\"supersetColors\",\"show_labels_threshold\":5,\"show_legend\":true,\"legendType\":\"scroll\",\"legendOrientation\":\"top\",\"label_type\":\"key\",\"number_format\":\"SMART_NUMBER\",\"date_format\":\"smart_date\",\"show_labels\":true,\"labels_outside\":true,\"outerRadius\":70,\"innerRadius\":30,\"extra_form_data\":{},\"force\":false,\"result_format\":\"json\",\"result_type\":\"full\"},\"result_format\":\"json\",\"result_type\":\"full\"}",
                            "slice_name": "Technical Debt",
                            "viz_type": "pie"
                        }
                    },
                    {
                        "__Slice__": {
                            "cache_timeout": null,
                            "datasource_name": "public.cloud_readiness_view",
                            "datasource_type": "table",
                            "id": 2,
                            "params": "{\"adhoc_filters\": [], \"bottom_margin\": \"auto\", \"color_scheme\": \"supersetColors\", \"columns\": [], \"datasource\": \"102__table\", \"extra_form_data\": {}, \"groupby\": [\"Application Name\"], \"metrics\": [{\"aggregate\": \"AVG\", \"column\": {\"certification_details\": null, \"certified_by\": null, \"column_name\": \"Cloud Readiness\", \"description\": null, \"expression\": null, \"filterable\": true, \"groupby\": true, \"id\": 1013, \"is_certified\": false, \"is_dttm\": false, \"python_date_format\": null, \"type\": \"DOUBLE PRECISION\", \"type_generic\": 0, \"verbose_name\": null, \"warning_markdown\": null}, \"expressionType\": \"SIMPLE\", \"hasCustomLabel\": false, \"isNew\": false, \"label\": \"AVG(Cloud Readiness)\", \"optionName\": \"metric_30yq9nmjo9o_cbzx23nbo8v\", \"sqlExpression\": null}], \"order_desc\": true, \"rich_tooltip\": true, \"row_limit\": 10000, \"time_range\": \"No filter\", \"time_range_endpoints\": [\"inclusive\", \"exclusive\"], \"url_params\": {}, \"viz_type\": \"dist_bar\", \"x_axis_label\": \"Application Name\", \"x_ticks_layout\": \"auto\", \"y_axis_bounds\": [0, null], \"y_axis_format\": \"SMART_NUMBER\", \"y_axis_label\": \"Cloud Readiness\", \"y_axis_showminmax\": false, \"remote_id\": 2, \"datasource_name\": \"cloud_readiness_view\", \"schema\": \"public\", \"database_name\": \"{{ .Values.supersetDatabase_name }}\"}",
                            "query_context": "{\"datasource\":{\"id\":102,\"type\":\"table\"},\"force\":false,\"queries\":[{\"time_range\":\"No filter\",\"filters\":[],\"extras\":{\"time_range_endpoints\":[\"inclusive\",\"exclusive\"],\"having\":\"\",\"having_druid\":[],\"where\":\"\"},\"applied_time_extras\":{},\"columns\":[\"Application Name\"],\"metrics\":[{\"expressionType\":\"SIMPLE\",\"column\":{\"id\":1013,\"column_name\":\"Cloud Readiness\",\"verbose_name\":null,\"description\":null,\"expression\":null,\"filterable\":true,\"groupby\":true,\"is_dttm\":false,\"type\":\"DOUBLE PRECISION\",\"type_generic\":0,\"python_date_format\":null,\"is_certified\":false,\"certified_by\":null,\"certification_details\":null,\"warning_markdown\":null},\"aggregate\":\"AVG\",\"sqlExpression\":null,\"isNew\":false,\"hasCustomLabel\":false,\"label\":\"AVG(Cloud Readiness)\",\"optionName\":\"metric_30yq9nmjo9o_cbzx23nbo8v\"}],\"annotation_layers\":[],\"row_limit\":10000,\"timeseries_limit\":0,\"order_desc\":true,\"url_params\":{},\"custom_params\":{},\"custom_form_data\":{}}],\"form_data\":{\"viz_type\":\"dist_bar\",\"datasource\":\"102__table\",\"url_params\":{},\"time_range_endpoints\":[\"inclusive\",\"exclusive\"],\"time_range\":\"No filter\",\"metrics\":[{\"expressionType\":\"SIMPLE\",\"column\":{\"id\":1013,\"column_name\":\"Cloud Readiness\",\"verbose_name\":null,\"description\":null,\"expression\":null,\"filterable\":true,\"groupby\":true,\"is_dttm\":false,\"type\":\"DOUBLE PRECISION\",\"type_generic\":0,\"python_date_format\":null,\"is_certified\":false,\"certified_by\":null,\"certification_details\":null,\"warning_markdown\":null},\"aggregate\":\"AVG\",\"sqlExpression\":null,\"isNew\":false,\"hasCustomLabel\":false,\"label\":\"AVG(Cloud Readiness)\",\"optionName\":\"metric_30yq9nmjo9o_cbzx23nbo8v\"}],\"adhoc_filters\":[],\"groupby\":[\"Application Name\"],\"columns\":[],\"row_limit\":10000,\"order_desc\":true,\"color_scheme\":\"supersetColors\",\"rich_tooltip\":true,\"y_axis_format\":\"SMART_NUMBER\",\"y_axis_label\":\"Cloud Readiness\",\"y_axis_showminmax\":false,\"y_axis_bounds\":[0,null],\"x_axis_label\":\"Application Name\",\"bottom_margin\":\"auto\",\"x_ticks_layout\":\"auto\",\"extra_form_data\":{},\"force\":false,\"result_format\":\"json\",\"result_type\":\"full\"},\"result_format\":\"json\",\"result_type\":\"full\"}",
                            "slice_name": "Cloud Readiness",
                            "viz_type": "dist_bar"
                        }
                    },
                    {
                        "__Slice__": {
                            "cache_timeout": null,
                            "datasource_name": "public.application_health_view",
                            "datasource_type": "table",
                            "id": 3,
                            "params": "{\"adhoc_filters\": [], \"bottom_margin\": \"auto\", \"color_scheme\": \"supersetColors\", \"datasource\": \"100__table\", \"entity\": \"Application Name\", \"extra_form_data\": {}, \"granularity_sqla\": \"Date\", \"left_margin\": \"auto\", \"max_bubble_size\": \"25\", \"series\": \"Technology\", \"size\": {\"aggregate\": \"COUNT\", \"column\": {\"certification_details\": null, \"certified_by\": null, \"column_name\": \"Critical\", \"description\": null, \"expression\": null, \"filterable\": true, \"groupby\": true, \"id\": 1000, \"is_certified\": false, \"is_dttm\": false, \"python_date_format\": null, \"type\": \"NUMERIC\", \"type_generic\": 0, \"verbose_name\": null, \"warning_markdown\": null}, \"expressionType\": \"SIMPLE\", \"hasCustomLabel\": false, \"isNew\": false, \"label\": \"COUNT(Critical)\", \"optionName\": \"metric_dghqmd0oi7q_zfvm7ozsdyb\", \"sqlExpression\": null}, \"slice_id\": 3, \"time_range\": \"No filter\", \"time_range_endpoints\": [\"inclusive\", \"exclusive\"], \"url_params\": {\"form_data_key\": \"ePAjTcrlckJu8bpRBfsiqlVAelj9PQQzojPxNpwRcbnHGgX1t9UiYwNH2gObMUN5\", \"native_filters_key\": \"FM_HUKdWLxECAFJWr7cLlVicwV1JYXQyHNcI1Rf84uTgUPmL2ZA0OfbROVp4qgue\", \"slice_id\": \"3\"}, \"viz_type\": \"bubble\", \"x\": {\"aggregate\": \"AVG\", \"column\": {\"certification_details\": null, \"certified_by\": null, \"column_name\": \"CAST HL Tech Debt\", \"description\": null, \"expression\": null, \"filterable\": true, \"groupby\": true, \"id\": 995, \"is_certified\": false, \"is_dttm\": false, \"python_date_format\": null, \"type\": \"DOUBLE PRECISION\", \"type_generic\": 0, \"verbose_name\": null, \"warning_markdown\": null}, \"expressionType\": \"SIMPLE\", \"hasCustomLabel\": false, \"isNew\": false, \"label\": \"AVG(CAST HL Tech Debt)\", \"optionName\": \"metric_4omge2i2eix_myw5ax97sb\", \"sqlExpression\": null}, \"x_axis_format\": \"SMART_NUMBER\", \"x_axis_label\": \"Technical Debt\", \"x_axis_showminmax\": false, \"x_log_scale\": false, \"x_ticks_layout\": \"auto\", \"y\": {\"aggregate\": \"AVG\", \"column\": {\"certification_details\": null, \"certified_by\": null, \"column_name\": \"Cloud Readiness\", \"description\": null, \"expression\": null, \"filterable\": true, \"groupby\": true, \"id\": 1004, \"is_certified\": false, \"is_dttm\": false, \"python_date_format\": null, \"type\": \"DOUBLE PRECISION\", \"type_generic\": 0, \"verbose_name\": null, \"warning_markdown\": null}, \"expressionType\": \"SIMPLE\", \"hasCustomLabel\": false, \"isNew\": false, \"label\": \"AVG(Cloud Readiness)\", \"optionName\": \"metric_rds5so4o44_iaxdclvbnjo\", \"sqlExpression\": null}, \"y_axis_bounds\": [null, null], \"y_axis_format\": \"SMART_NUMBER\", \"y_axis_label\": \"Cloud Readiness\", \"y_axis_showminmax\": false, \"remote_id\": 3, \"datasource_name\": \"application_health_view\", \"schema\": \"public\", \"database_name\": \"{{ .Values.supersetDatabase_name }}\"}",
                            "query_context": "{\"datasource\":{\"id\":100,\"type\":\"table\"},\"force\":false,\"queries\":[{\"time_range\":\"No filter\",\"granularity\":\"Date\",\"filters\":[],\"extras\":{\"time_range_endpoints\":[\"inclusive\",\"exclusive\"],\"having\":\"\",\"having_druid\":[],\"where\":\"\"},\"applied_time_extras\":{},\"columns\":[\"Technology\"],\"metrics\":[{\"aggregate\":\"AVG\",\"column\":{\"certification_details\":null,\"certified_by\":null,\"column_name\":\"CAST HL Tech Debt\",\"description\":null,\"expression\":null,\"filterable\":true,\"groupby\":true,\"id\":995,\"is_certified\":false,\"is_dttm\":false,\"python_date_format\":null,\"type\":\"DOUBLE PRECISION\",\"type_generic\":0,\"verbose_name\":null,\"warning_markdown\":null},\"expressionType\":\"SIMPLE\",\"hasCustomLabel\":false,\"isNew\":false,\"label\":\"AVG(CAST HL Tech Debt)\",\"optionName\":\"metric_4omge2i2eix_myw5ax97sb\",\"sqlExpression\":null},{\"aggregate\":\"AVG\",\"column\":{\"certification_details\":null,\"certified_by\":null,\"column_name\":\"Cloud Readiness\",\"description\":null,\"expression\":null,\"filterable\":true,\"groupby\":true,\"id\":1004,\"is_certified\":false,\"is_dttm\":false,\"python_date_format\":null,\"type\":\"DOUBLE PRECISION\",\"type_generic\":0,\"verbose_name\":null,\"warning_markdown\":null},\"expressionType\":\"SIMPLE\",\"hasCustomLabel\":false,\"isNew\":false,\"label\":\"AVG(Cloud Readiness)\",\"optionName\":\"metric_rds5so4o44_iaxdclvbnjo\",\"sqlExpression\":null},{\"aggregate\":\"COUNT\",\"column\":{\"certification_details\":null,\"certified_by\":null,\"column_name\":\"Critical\",\"description\":null,\"expression\":null,\"filterable\":true,\"groupby\":true,\"id\":1000,\"is_certified\":false,\"is_dttm\":false,\"python_date_format\":null,\"type\":\"NUMERIC\",\"type_generic\":0,\"verbose_name\":null,\"warning_markdown\":null},\"expressionType\":\"SIMPLE\",\"hasCustomLabel\":false,\"isNew\":false,\"label\":\"COUNT(Critical)\",\"optionName\":\"metric_dghqmd0oi7q_zfvm7ozsdyb\",\"sqlExpression\":null}],\"annotation_layers\":[],\"timeseries_limit\":0,\"order_desc\":true,\"url_params\":{\"native_filters_key\":\"FM_HUKdWLxECAFJWr7cLlVicwV1JYXQyHNcI1Rf84uTgUPmL2ZA0OfbROVp4qgue\",\"form_data_key\":\"ePAjTcrlckJu8bpRBfsiqlVAelj9PQQzojPxNpwRcbnHGgX1t9UiYwNH2gObMUN5\",\"slice_id\":\"3\"},\"custom_params\":{},\"custom_form_data\":{}}],\"form_data\":{\"viz_type\":\"bubble\",\"datasource\":\"100__table\",\"slice_id\":3,\"url_params\":{\"native_filters_key\":\"FM_HUKdWLxECAFJWr7cLlVicwV1JYXQyHNcI1Rf84uTgUPmL2ZA0OfbROVp4qgue\",\"form_data_key\":\"ePAjTcrlckJu8bpRBfsiqlVAelj9PQQzojPxNpwRcbnHGgX1t9UiYwNH2gObMUN5\",\"slice_id\":\"3\"},\"time_range_endpoints\":[\"inclusive\",\"exclusive\"],\"granularity_sqla\":\"Date\",\"time_range\":\"No filter\",\"series\":\"Technology\",\"entity\":\"Application Name\",\"x\":{\"aggregate\":\"AVG\",\"column\":{\"certification_details\":null,\"certified_by\":null,\"column_name\":\"CAST HL Tech Debt\",\"description\":null,\"expression\":null,\"filterable\":true,\"groupby\":true,\"id\":995,\"is_certified\":false,\"is_dttm\":false,\"python_date_format\":null,\"type\":\"DOUBLE PRECISION\",\"type_generic\":0,\"verbose_name\":null,\"warning_markdown\":null},\"expressionType\":\"SIMPLE\",\"hasCustomLabel\":false,\"isNew\":false,\"label\":\"AVG(CAST HL Tech Debt)\",\"optionName\":\"metric_4omge2i2eix_myw5ax97sb\",\"sqlExpression\":null},\"y\":{\"aggregate\":\"AVG\",\"column\":{\"certification_details\":null,\"certified_by\":null,\"column_name\":\"Cloud Readiness\",\"description\":null,\"expression\":null,\"filterable\":true,\"groupby\":true,\"id\":1004,\"is_certified\":false,\"is_dttm\":false,\"python_date_format\":null,\"type\":\"DOUBLE PRECISION\",\"type_generic\":0,\"verbose_name\":null,\"warning_markdown\":null},\"expressionType\":\"SIMPLE\",\"hasCustomLabel\":false,\"isNew\":false,\"label\":\"AVG(Cloud Readiness)\",\"optionName\":\"metric_rds5so4o44_iaxdclvbnjo\",\"sqlExpression\":null},\"adhoc_filters\":[],\"size\":{\"aggregate\":\"COUNT\",\"column\":{\"certification_details\":null,\"certified_by\":null,\"column_name\":\"Critical\",\"description\":null,\"expression\":null,\"filterable\":true,\"groupby\":true,\"id\":1000,\"is_certified\":false,\"is_dttm\":false,\"python_date_format\":null,\"type\":\"NUMERIC\",\"type_generic\":0,\"verbose_name\":null,\"warning_markdown\":null},\"expressionType\":\"SIMPLE\",\"hasCustomLabel\":false,\"isNew\":false,\"label\":\"COUNT(Critical)\",\"optionName\":\"metric_dghqmd0oi7q_zfvm7ozsdyb\",\"sqlExpression\":null},\"max_bubble_size\":\"25\",\"color_scheme\":\"supersetColors\",\"x_axis_label\":\"Technical Debt\",\"left_margin\":\"auto\",\"x_axis_format\":\"SMART_NUMBER\",\"x_ticks_layout\":\"auto\",\"x_log_scale\":false,\"x_axis_showminmax\":false,\"y_axis_label\":\"Cloud Readiness\",\"bottom_margin\":\"auto\",\"y_axis_format\":\"SMART_NUMBER\",\"y_axis_showminmax\":false,\"y_axis_bounds\":[null,null],\"extra_form_data\":{},\"force\":false,\"result_format\":\"json\",\"result_type\":\"full\"},\"result_format\":\"json\",\"result_type\":\"full\"}",
                            "slice_name": "Application Health",
                            "viz_type": "bubble"
                        }
                    }
                ],
                "slug": null
            }
        }
    ],
    "datasources": [
        {
            "__SqlaTable__": {
                "cache_timeout": null,
                "columns": [
                    {
                        "__TableColumn__": {
                            "changed_by_fk": 1,
                            "changed_on": {
                                "__datetime__": "2022-02-14T14:58:03"
                            },
                            "column_name": "Application Name",
                            "created_by_fk": 1,
                            "created_on": {
                                "__datetime__": "2022-02-14T14:58:03"
                            },
                            "description": null,
                            "expression": null,
                            "extra": null,
                            "filterable": true,
                            "groupby": true,
                            "id": 1011,
                            "is_active": true,
                            "is_dttm": false,
                            "python_date_format": null,
                            "table_id": 102,
                            "type": "VARCHAR(255)",
                            "uuid": "5a0b9fd4-df16-42c3-9ca2-c7837abc98b6",
                            "verbose_name": null
                        }
                    },
                    {
                        "__TableColumn__": {
                            "changed_by_fk": 1,
                            "changed_on": {
                                "__datetime__": "2022-02-14T14:58:03"
                            },
                            "column_name": "Technology",
                            "created_by_fk": 1,
                            "created_on": {
                                "__datetime__": "2022-02-14T14:58:03"
                            },
                            "description": null,
                            "expression": null,
                            "extra": null,
                            "filterable": true,
                            "groupby": true,
                            "id": 1012,
                            "is_active": true,
                            "is_dttm": false,
                            "python_date_format": null,
                            "table_id": 102,
                            "type": "VARCHAR(255)",
                            "uuid": "96b42a8f-42ce-450f-853c-9b3628474450",
                            "verbose_name": null
                        }
                    },
                    {
                        "__TableColumn__": {
                            "changed_by_fk": 1,
                            "changed_on": {
                                "__datetime__": "2022-02-14T14:58:03"
                            },
                            "column_name": "Cloud Readiness",
                            "created_by_fk": 1,
                            "created_on": {
                                "__datetime__": "2022-02-14T14:58:03"
                            },
                            "description": null,
                            "expression": null,
                            "extra": null,
                            "filterable": true,
                            "groupby": true,
                            "id": 1013,
                            "is_active": true,
                            "is_dttm": false,
                            "python_date_format": null,
                            "table_id": 102,
                            "type": "DOUBLE PRECISION",
                            "uuid": "1d26b307-3193-46d9-bf8f-9ef4baddd547",
                            "verbose_name": null
                        }
                    }
                ],
                "database_id": 1,
                "default_endpoint": null,
                "description": null,
                "extra": null,
                "fetch_values_predicate": null,
                "filter_select_enabled": false,
                "main_dttm_col": null,
                "metrics": [
                    {
                        "__SqlMetric__": {
                            "changed_by_fk": 1,
                            "changed_on": {
                                "__datetime__": "2022-02-14T14:58:03"
                            },
                            "created_by_fk": 1,
                            "created_on": {
                                "__datetime__": "2022-02-14T14:58:03"
                            },
                            "d3format": null,
                            "description": null,
                            "expression": "COUNT(*)",
                            "extra": null,
                            "id": 102,
                            "metric_name": "count",
                            "metric_type": "count",
                            "table_id": 102,
                            "uuid": "62855bc5-ce18-475e-a7b5-ff95631e243f",
                            "verbose_name": "COUNT(*)",
                            "warning_text": null
                        }
                    }
                ],
                "offset": 0,
                "params": "{\"remote_id\": 102, \"database_name\": \"{{ .Values.supersetDatabase_name }}\"}",
                "schema": "public",
                "sql": null,
                "table_name": "cloud_readiness_view",
                "template_params": null
            }
        },
        {
            "__SqlaTable__": {
                "cache_timeout": null,
                "columns": [
                    {
                        "__TableColumn__": {
                            "changed_by_fk": 1,
                            "changed_on": {
                                "__datetime__": "2022-02-11T19:58:55"
                            },
                            "column_name": "Application Name",
                            "created_by_fk": 1,
                            "created_on": {
                                "__datetime__": "2022-02-11T19:58:55"
                            },
                            "description": null,
                            "expression": null,
                            "extra": null,
                            "filterable": true,
                            "groupby": true,
                            "id": 994,
                            "is_active": true,
                            "is_dttm": false,
                            "python_date_format": null,
                            "table_id": 100,
                            "type": "VARCHAR(255)",
                            "uuid": "facde879-85b2-4c6a-a150-ef32480c51db",
                            "verbose_name": null
                        }
                    },
                    {
                        "__TableColumn__": {
                            "changed_by_fk": 1,
                            "changed_on": {
                                "__datetime__": "2022-02-11T19:58:55"
                            },
                            "column_name": "CAST HL Tech Debt",
                            "created_by_fk": 1,
                            "created_on": {
                                "__datetime__": "2022-02-11T19:58:55"
                            },
                            "description": null,
                            "expression": null,
                            "extra": null,
                            "filterable": true,
                            "groupby": true,
                            "id": 995,
                            "is_active": true,
                            "is_dttm": false,
                            "python_date_format": null,
                            "table_id": 100,
                            "type": "DOUBLE PRECISION",
                            "uuid": "c6e2e35a-af67-48d7-81f5-56f1beef44d1",
                            "verbose_name": null
                        }
                    },
                    {
                        "__TableColumn__": {
                            "changed_by_fk": 1,
                            "changed_on": {
                                "__datetime__": "2022-02-11T19:58:55"
                            },
                            "column_name": "Sonarqube Tech Debt",
                            "created_by_fk": 1,
                            "created_on": {
                                "__datetime__": "2022-02-11T19:58:55"
                            },
                            "description": null,
                            "expression": null,
                            "extra": null,
                            "filterable": true,
                            "groupby": true,
                            "id": 996,
                            "is_active": true,
                            "is_dttm": false,
                            "python_date_format": null,
                            "table_id": 100,
                            "type": "DOUBLE PRECISION",
                            "uuid": "6ec86f86-cd4e-4cd8-9a72-56f6dca74927",
                            "verbose_name": null
                        }
                    },
                    {
                        "__TableColumn__": {
                            "changed_by_fk": 1,
                            "changed_on": {
                                "__datetime__": "2022-02-11T19:58:55"
                            },
                            "column_name": "Date",
                            "created_by_fk": 1,
                            "created_on": {
                                "__datetime__": "2022-02-11T19:58:55"
                            },
                            "description": null,
                            "expression": null,
                            "extra": null,
                            "filterable": true,
                            "groupby": true,
                            "id": 997,
                            "is_active": true,
                            "is_dttm": true,
                            "python_date_format": null,
                            "table_id": 100,
                            "type": "DATE",
                            "uuid": "1e19e0a2-5d7a-4375-9a7a-aca17346933f",
                            "verbose_name": null
                        }
                    },
                    {
                        "__TableColumn__": {
                            "changed_by_fk": 1,
                            "changed_on": {
                                "__datetime__": "2022-02-11T19:58:55"
                            },
                            "column_name": "Application",
                            "created_by_fk": 1,
                            "created_on": {
                                "__datetime__": "2022-02-11T19:58:55"
                            },
                            "description": null,
                            "expression": null,
                            "extra": null,
                            "filterable": true,
                            "groupby": true,
                            "id": 998,
                            "is_active": true,
                            "is_dttm": false,
                            "python_date_format": null,
                            "table_id": 100,
                            "type": "VARCHAR(255)",
                            "uuid": "12040624-cd4f-43e2-8eb7-a49b5cc6cadf",
                            "verbose_name": null
                        }
                    },
                    {
                        "__TableColumn__": {
                            "changed_by_fk": 1,
                            "changed_on": {
                                "__datetime__": "2022-02-11T19:58:55"
                            },
                            "column_name": "Technology",
                            "created_by_fk": 1,
                            "created_on": {
                                "__datetime__": "2022-02-11T19:58:55"
                            },
                            "description": null,
                            "expression": null,
                            "extra": null,
                            "filterable": true,
                            "groupby": true,
                            "id": 999,
                            "is_active": true,
                            "is_dttm": false,
                            "python_date_format": null,
                            "table_id": 100,
                            "type": "VARCHAR(255)",
                            "uuid": "ff7d2ac7-1d5d-4965-b141-75b7dbabbe20",
                            "verbose_name": null
                        }
                    },
                    {
                        "__TableColumn__": {
                            "changed_by_fk": 1,
                            "changed_on": {
                                "__datetime__": "2022-02-11T19:58:55"
                            },
                            "column_name": "Critical",
                            "created_by_fk": 1,
                            "created_on": {
                                "__datetime__": "2022-02-11T19:58:55"
                            },
                            "description": null,
                            "expression": null,
                            "extra": null,
                            "filterable": true,
                            "groupby": true,
                            "id": 1000,
                            "is_active": true,
                            "is_dttm": false,
                            "python_date_format": null,
                            "table_id": 100,
                            "type": "NUMERIC",
                            "uuid": "bf0c8265-b2a9-412c-8d55-2e4a4cd132f0",
                            "verbose_name": null
                        }
                    },
                    {
                        "__TableColumn__": {
                            "changed_by_fk": 1,
                            "changed_on": {
                                "__datetime__": "2022-02-11T19:58:55"
                            },
                            "column_name": "High",
                            "created_by_fk": 1,
                            "created_on": {
                                "__datetime__": "2022-02-11T19:58:55"
                            },
                            "description": null,
                            "expression": null,
                            "extra": null,
                            "filterable": true,
                            "groupby": true,
                            "id": 1001,
                            "is_active": true,
                            "is_dttm": false,
                            "python_date_format": null,
                            "table_id": 100,
                            "type": "NUMERIC",
                            "uuid": "f038c3c2-160c-4ee7-baf8-bda36d9882a4",
                            "verbose_name": null
                        }
                    },
                    {
                        "__TableColumn__": {
                            "changed_by_fk": 1,
                            "changed_on": {
                                "__datetime__": "2022-02-11T19:58:55"
                            },
                            "column_name": "Moderate",
                            "created_by_fk": 1,
                            "created_on": {
                                "__datetime__": "2022-02-11T19:58:55"
                            },
                            "description": null,
                            "expression": null,
                            "extra": null,
                            "filterable": true,
                            "groupby": true,
                            "id": 1002,
                            "is_active": true,
                            "is_dttm": false,
                            "python_date_format": null,
                            "table_id": 100,
                            "type": "NUMERIC",
                            "uuid": "6917bc48-a24c-447e-9327-e343b6b1aeda",
                            "verbose_name": null
                        }
                    },
                    {
                        "__TableColumn__": {
                            "changed_by_fk": 1,
                            "changed_on": {
                                "__datetime__": "2022-02-11T19:58:55"
                            },
                            "column_name": "Low",
                            "created_by_fk": 1,
                            "created_on": {
                                "__datetime__": "2022-02-11T19:58:55"
                            },
                            "description": null,
                            "expression": null,
                            "extra": null,
                            "filterable": true,
                            "groupby": true,
                            "id": 1003,
                            "is_active": true,
                            "is_dttm": false,
                            "python_date_format": null,
                            "table_id": 100,
                            "type": "NUMERIC",
                            "uuid": "239dd9bf-c04d-4909-a8f7-cc6b0b16cf6d",
                            "verbose_name": null
                        }
                    },
                    {
                        "__TableColumn__": {
                            "changed_by_fk": 1,
                            "changed_on": {
                                "__datetime__": "2022-02-11T19:58:55"
                            },
                            "column_name": "Cloud Readiness",
                            "created_by_fk": 1,
                            "created_on": {
                                "__datetime__": "2022-02-11T19:58:55"
                            },
                            "description": null,
                            "expression": null,
                            "extra": null,
                            "filterable": true,
                            "groupby": true,
                            "id": 1004,
                            "is_active": true,
                            "is_dttm": false,
                            "python_date_format": null,
                            "table_id": 100,
                            "type": "DOUBLE PRECISION",
                            "uuid": "f7b02728-ca07-4c0f-be85-08fcb8f50365",
                            "verbose_name": null
                        }
                    }
                ],
                "database_id": 1,
                "default_endpoint": null,
                "description": null,
                "extra": null,
                "fetch_values_predicate": null,
                "filter_select_enabled": false,
                "main_dttm_col": "Date",
                "metrics": [
                    {
                        "__SqlMetric__": {
                            "changed_by_fk": 1,
                            "changed_on": {
                                "__datetime__": "2022-02-11T19:58:55"
                            },
                            "created_by_fk": 1,
                            "created_on": {
                                "__datetime__": "2022-02-11T19:58:55"
                            },
                            "d3format": null,
                            "description": null,
                            "expression": "COUNT(*)",
                            "extra": null,
                            "id": 100,
                            "metric_name": "count",
                            "metric_type": "count",
                            "table_id": 100,
                            "uuid": "cb215bdd-04c8-40dd-86f9-c09e5088b982",
                            "verbose_name": "COUNT(*)",
                            "warning_text": null
                        }
                    }
                ],
                "offset": 0,
                "params": "{\"remote_id\": 100, \"database_name\": \"{{ .Values.supersetDatabase_name }}\"}",
                "schema": "public",
                "sql": null,
                "table_name": "application_health_view",
                "template_params": null
            }
        },
        {
            "__SqlaTable__": {
                "cache_timeout": null,
                "columns": [
                    {
                        "__TableColumn__": {
                            "changed_by_fk": 1,
                            "changed_on": {
                                "__datetime__": "2022-02-14T14:58:15"
                            },
                            "column_name": "Application Name",
                            "created_by_fk": 1,
                            "created_on": {
                                "__datetime__": "2022-02-14T14:58:15"
                            },
                            "description": null,
                            "expression": null,
                            "extra": null,
                            "filterable": true,
                            "groupby": true,
                            "id": 1014,
                            "is_active": true,
                            "is_dttm": false,
                            "python_date_format": null,
                            "table_id": 103,
                            "type": "VARCHAR(255)",
                            "uuid": "0a1d8b28-6690-4e64-8dfa-f1dc7db8175c",
                            "verbose_name": null
                        }
                    },
                    {
                        "__TableColumn__": {
                            "changed_by_fk": 1,
                            "changed_on": {
                                "__datetime__": "2022-02-14T14:58:15"
                            },
                            "column_name": "CAST HL Tech Debt",
                            "created_by_fk": 1,
                            "created_on": {
                                "__datetime__": "2022-02-14T14:58:15"
                            },
                            "description": null,
                            "expression": null,
                            "extra": null,
                            "filterable": true,
                            "groupby": true,
                            "id": 1015,
                            "is_active": true,
                            "is_dttm": false,
                            "python_date_format": null,
                            "table_id": 103,
                            "type": "DOUBLE PRECISION",
                            "uuid": "52c92460-1298-4a2a-b633-94953cc1494b",
                            "verbose_name": null
                        }
                    },
                    {
                        "__TableColumn__": {
                            "changed_by_fk": 1,
                            "changed_on": {
                                "__datetime__": "2022-02-14T14:58:15"
                            },
                            "column_name": "Sonarqube Tech Debt",
                            "created_by_fk": 1,
                            "created_on": {
                                "__datetime__": "2022-02-14T14:58:15"
                            },
                            "description": null,
                            "expression": null,
                            "extra": null,
                            "filterable": true,
                            "groupby": true,
                            "id": 1016,
                            "is_active": true,
                            "is_dttm": false,
                            "python_date_format": null,
                            "table_id": 103,
                            "type": "DOUBLE PRECISION",
                            "uuid": "78358531-8356-440d-bf64-765a014bb9ab",
                            "verbose_name": null
                        }
                    },
                    {
                        "__TableColumn__": {
                            "changed_by_fk": 1,
                            "changed_on": {
                                "__datetime__": "2022-02-14T14:58:15"
                            },
                            "column_name": "Date",
                            "created_by_fk": 1,
                            "created_on": {
                                "__datetime__": "2022-02-14T14:58:15"
                            },
                            "description": null,
                            "expression": null,
                            "extra": null,
                            "filterable": true,
                            "groupby": true,
                            "id": 1017,
                            "is_active": true,
                            "is_dttm": true,
                            "python_date_format": null,
                            "table_id": 103,
                            "type": "DATE",
                            "uuid": "651407b8-142c-4018-8c04-7bd1526e2f11",
                            "verbose_name": null
                        }
                    }
                ],
                "database_id": 1,
                "default_endpoint": null,
                "description": null,
                "extra": null,
                "fetch_values_predicate": null,
                "filter_select_enabled": false,
                "main_dttm_col": "Date",
                "metrics": [
                    {
                        "__SqlMetric__": {
                            "changed_by_fk": 1,
                            "changed_on": {
                                "__datetime__": "2022-02-14T14:58:15"
                            },
                            "created_by_fk": 1,
                            "created_on": {
                                "__datetime__": "2022-02-14T14:58:15"
                            },
                            "d3format": null,
                            "description": null,
                            "expression": "COUNT(*)",
                            "extra": null,
                            "id": 103,
                            "metric_name": "count",
                            "metric_type": "count",
                            "table_id": 103,
                            "uuid": "a8527131-396f-4028-9624-cf795f36bc6e",
                            "verbose_name": "COUNT(*)",
                            "warning_text": null
                        }
                    }
                ],
                "offset": 0,
                "params": "{\"remote_id\": 103, \"database_name\": \"{{ .Values.supersetDatabase_name }}\"}",
                "schema": "public",
                "sql": null,
                "table_name": "technical_debt_view",
                "template_params": null
            }
        }
    ]
}
{{- end}}
