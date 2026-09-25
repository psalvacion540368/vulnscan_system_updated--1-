from django.urls import path
from . import views

app_name = "scanning"

urlpatterns = [
    path("", views.job_list, name="job_list"),
    path("targets/add/", views.add_target, name="add_target"),
    path("targets/wifi/", views.wifi_targets, name="wifi_targets"),
    path("launch/", views.launch_scan, name="launch_scan"),
    path("jobs/<int:job_id>/", views.job_detail, name="job_detail"),
    path("jobs/<int:job_id>/status/", views.job_status, name="job_status"),
    path("jobs/<int:job_id>/compare/", views.job_compare, name="job_compare"),
    path("targets/<int:target_id>/trend/", views.target_trend, name="target_trend"),
]
