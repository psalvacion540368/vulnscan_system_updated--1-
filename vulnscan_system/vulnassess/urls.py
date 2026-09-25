from django.urls import path
from . import views

app_name = "vulnassess"

urlpatterns = [
    path("", views.findings_list, name="findings_list"),
    path("<int:finding_id>/", views.finding_detail, name="finding_detail"),
]
