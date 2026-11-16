from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('', views.index, name='index'),
    path('api/events/', views.api_events, name='api_events'),
    path('api/event/<int:event_id>/', views.api_event_detail, name='api_event_detail'),
    path('api/attack-graph/', views.api_attack_graph, name='api_attack_graph'),
    path('api/attack-graph-data/', views.api_attack_graph_data, name='api_attack_graph_data'),
    path('api/attack-graph-element/', views.api_attack_graph_element, name='api_attack_graph_element'),
    path('api/ingest/', views.api_ingest, name='api_ingest'),
    path('api/load-samples/', views.api_load_samples, name='api_load_samples'),
    path('api/load-scenario/<str:name>/', views.api_load_scenario, name='api_load_scenario'),
    path('api/verify/', views.api_verify, name='api_verify'),
    path('api/tamper/', views.api_tamper, name='api_tamper'),
    path('api/restore-evidence/', views.api_restore_evidence, name='api_restore_evidence'),
    path('api/reset/', views.api_reset, name='api_reset'),
    path('export/<str:fmt>/', views.export_report, name='export_report'),
    path('api/ai/narrative/', views.api_ai_narrative, name='api_ai_narrative'),
    path('api/ai/ask/', views.api_ai_ask, name='api_ai_ask'),
    path('api/ai/gap/', views.api_ai_gap, name='api_ai_gap'),
]

