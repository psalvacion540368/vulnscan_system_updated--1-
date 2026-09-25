from django.urls import path
from . import views

app_name = "reporting"

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("analytics/", views.analytics, name="analytics"),
    path(
        "reports/",
        views.report_list,
        name="report_list",
    ),
    path(
        "reports/generate/<int:job_id>/<str:fmt>/",
        views.generate_report,
        name="generate_report",
    ),
]
