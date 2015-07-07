from __future__ import unicode_literals
import json
from django.shortcuts import render

# Create your views here.
from django.template import loader,Context
from django.http import HttpResponse
from models import RadioItem,PhoneUser
from django.core import serializers

def fmitem(request):
    objs = RadioItem.objects.all()
    nobjs = [ {'link': x.__dict__['link'],'title':x.__dict__['title'],'id':x.__dict__['id']} for x in objs]
    #data = serializers.serialize('json',nobjs)
    data = json.dumps(nobjs)
    return HttpResponse(data,content_type='text/json')

def AddRadioItem(request):
    mms = request.GET['link']
    tname = request.GET['title']
    RadioItem.objects.create(link = mms,title = tname)
    return HttpResponse('{state: ok}')


def PhoneLogin(request):
    model = request.GET['model']
    imei = request.GET['imei']
    addr = request.GET['ipaddr']
    PhoneUser.objects.create(pmodel=model,pimei=imei,paddr=addr)
    return HttpResponse('{state: ok}')
#    except:
#        return HttpResponse('{state: register failed}')
#    else:
#        return HttpResponse('{state: ok}')

    




    

