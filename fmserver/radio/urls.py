from django.conf.urls import url
from .views import fmitem,PhoneLogin,AddRadioItem

from . import views

urlpatterns = [
        url(r'^item/$',fmitem),
        url(r'^register/$',PhoneLogin),
        url(r'^addradioitem/$',AddRadioItem),
        ]
