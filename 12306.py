#!/usr/bin/env python
# -*- encoding:utf-8 -*-
'''
Created on 2014年12月30日
 
@author: liujichao
'''
import sys
import logging
from splinter import Browser
import time
import threading
import getpass

logging.getLogger().setLevel(logging.ERROR)
reload(sys)
sys.setdefaultencoding('utf-8')  # @UndefinedVariable

def timer_refresh_ticket(btn):
    btn.click()
def checkTick():
    while True:
        if int(time.strftime("%H", time.localtime())) in [23,0,1,2,3,4,5,6]:
            print "23点到7点不能登录"
            time.sleep(200)
        else:
            break
    browser.visit("https://kyfw.12306.cn/otn/login/init")
    browser.find_by_id("username").fill(uname)
    browser.find_by_id("password").fill(pwd)
    browser.find_by_id("randCode").click()
     
    while True:       
        while len(browser.find_by_id("randCode").value)<4 or not browser.find_by_id("i-okmypasscode1").visible:
            time.sleep(1)
            pass
        browser.find_by_id("loginSub").click()
        warnAlert=browser.find_by_id("content_defaultwarningAlert_id")
        if  len(warnAlert)!=0 and warnAlert.visible:
            browser.find_by_id("qd_closeDefaultWarningWindowDialog_id").click()
            browser.execute_script('''refreshImg('login','sjrand');''')
            browser.find_by_id("randCode").click()
            continue
            pass
        break
        pass
    while browser.url !="https://kyfw.12306.cn/otn/index/initMy12306":
        print browser.url
        time.sleep(1)
        pass   
    browser.visit('https://kyfw.12306.cn/otn/leftTicket/init')
    #browser.fill('kw', 'splinter - python acceptance testing for web applications')
    #browser.execute_script("$('body').empty()")
    #print browser.find_by_id("login_user")
    #browser.find_by_id("login_user").click()
    #print browser.cookies()
     
    browser.find_by_id("fromStationText").click()
    browser.execute_script('''$(\"#ul_list1 > li:nth-child(9)\").click();
    ''')
     
    browser.find_by_id("toStationText").click()
    #$(\"a.cityflip:nth-child(1)\").click();
    browser.execute_script('''
    $(\"#nav_list5\").click();
    $.stationFor12306.pageDesigh(17,2,5);
    $(\"#ul_list5 > li:nth-child(6)\").click();
    $("#train_date").val("2015-02-14");
    ''')
    browser.find_by_id("show_more").click() #打开更多选项，添加乘车人等信息
    browser.execute_script('''
    $.showSelectBuyer();
    $(\"#buyer-list li input \").click();
    ''')
    browser.execute_script('''
    $.closeSelectBuyer();
    ''')
    #选择席别 
    browser.execute_script('''
    $.showSelectSeat();
    $(\"#seat-list .color333 \").find(\"input[value=YZ]\").click();
    $(\"#seat-list .color333 \").find(\"input[value=YW]\").click();
    $(\"#seat-list .color333 \").find(\"input[value=ZE]\").click();
    $.closeSelectSeat();
    ''')
    #browser.find_by_value('YZ').click()
    #browser.find_by_value('YW').click()
    #browser.find_by_value('ZE').click()


    tlist = ['K6546','K6542','G6142','K9084']
    ytext = browser.find_by_id('inp-train')
    ybtn = browser.find_by_id('add-train')


    btn = browser.find_by_id('query_ticket')
    tt =threading.Timer(2,timer_refresh_ticket,(btn))
    tt.start()
        
    browser.find_by_id('autoSubmit').check()
    
    

    #browser.find_by_value("G").check()
    #browser.find_by_id("train_date").click()
    #time.sleep(10)
    browser.execute_script('''
    setInterval(function(){
    $.ajax({
            type: 'post',
            url: '/otn/login/checkUser',
            data: {
            },
            beforeSend: function (c) {
                c.setRequestHeader('If-Modified-Since', '0');
                c.setRequestHeader('Cache-Control', 'no-cache')
            },
            success: function (e) {
                if (!e.data.flag) {
                   location.href="https://kyfw.12306.cn/otn/login/init";
                }
            }
        });
},2000);
    ''')
    while True:
        if browser.url=="https://kyfw.12306.cn/otn/login/init":
            #被踢了
            print "被踢了"
            raise Exception("被踢")
            pass
        browser.execute_script('''$("#train_date").val("2015-02-14");''')
        browser.find_by_id("query_ticket").click()
        browser.execute_script("CLeftTicketUrl = 'leftTicket/queryT?_r="+str(time.time())+"';")
        browser.execute_script('''$("#train_date").val("2015-02-14");''')
        warnAlert=browser.find_by_id("content_defaultwarningAlert_id")
        if  len(warnAlert)!=0:
            browser.find_by_id("qd_closeDefaultWarningWindowDialog_id").click()
            pass
        browser.execute_script('''
        iflagt=false;
$('#queryLeftTable tr').each(function () {
  trId = $(this).attr('id');
  if (/^ticket/.test(trId)) {
    tid=trId.replace("ticket_","");
    tranCode=$("#"+trId+"_train").find("a").text()
    if("K6546,K6542,G6142,K9084".indexOf(tranCode+",")!=-1){
        //二等座位
        ZEtxt=$("#ZE_"+tid).text();
        zcount=0;
        try
        {
         zcount=parseInt(ZEtxt)
        } catch (e) {zcount=0;}
      console.log(ZEtxt);
      txtInfo=$("#"+trId+">.no-br").text()
      if((ZEtxt=="有" || zcount>1) && txtInfo!="23:00-07:00系统维护时间"){
        $(this).find(".btn72").click();
        iflagt=true;
        return false;
      }
    }
     
  }
});
''')
         
        if browser.evaluate_script("iflagt;"):
            break
            pass
        else:
            print "无"
            pass
        time.sleep(3)

    while browser.url !="https://kyfw.12306.cn/otn/confirmPassenger/initDc":
        print browser.url
        time.sleep(1)
        pass  
    browser.find_by_id("gd").click()
    browser.find_by_id("normalPassenger_0").check()
    browser.find_by_id("normalPassenger_24").check()
    browser.find_by_id("randCode").click()
     
    while len(browser.find_by_id("randCode").value)<4:
        time.sleep(1)
        pass
    browser.is_element_not_present_by_id(id, wait_time=None)
    while not browser.find_by_id("checkticketinfo_id").visible:
        time.sleep(0.5)
        pass
    browser.find_by_id("qr_submit_id").click()
    #browser.find_by_id("fromStation").fill("BXP")
    #browser.find_by_id("train_date").fill("BXP")
    #browser.find_by_id("query_ticket").click()
    #print browser.html
    print browser.cookies.all()
    pass

if __name__ == '__main__':
    uname  = None
    pwd = None
    while True:
        uname = raw_input("用户名:")
        if len(uname) == 0:
            continue
        else:
            break
    while True:
        pwd = getpass.getpass("密码:")
        if len(pwd) == 0:
            continue
        else:
            break
    
    browser = Browser()
    while True:
        try:
            checkTick()
        except Exception,e:
            browser.quit()
            browser = Browser()
            print e
            pass
        pass
    pass
