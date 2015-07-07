#coding=utf-8
from django.db import models
from django.contrib import admin

# Create your models here.
class RadioItem(models.Model):
    title = models.CharField(max_length=150)
    link = models.CharField(max_length=255)

class PhoneUser(models.Model):
    pmodel = models.CharField(max_length=50) # 手机型号
    pimei = models.CharField(max_length=15) #IMEI
    paddr = models.GenericIPAddressField()
    
admin.site.register(RadioItem)
admin.site.register(PhoneUser)

