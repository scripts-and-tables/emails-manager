from django.urls import path

from . import views

app_name = "api"

urlpatterns = [
    path("messages", views.messages_recent, name="messages_recent"),
]
