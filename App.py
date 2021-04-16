import sqlite3
from tabulate import tabulate
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from scapy.layers.inet import traceroute
import graphviz
from napalm import get_network_driver
from flask import Flask, render_template, session, redirect, url_for, request, flash,Response
from flask_wtf import FlaskForm
from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoTimeoutException
from paramiko.ssh_exception import SSHException
from netmiko.ssh_exception import AuthenticationException
import json
import time
import matplotlib.pyplot as plt
import pandas as pd
import ipaddress
import os
from wtforms import (StringField, BooleanField,DateTimeField,
                    RadioField,SelectField,TextField,TextAreaField,PasswordField,
                    SubmitField)
from wtforms.validators import DataRequired
from netmiko import ConnectHandler

app = Flask(__name__)
#app.secret_key = "Secret Key"
app.config['SECRET_KEY']='imranawan'

# SqlAlchemy Database Configuration With Sqllite

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///NMSdata'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


# Creating model table for our CRUD database
class Data(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(100))
    username = db.Column(db.String(100))
    password = db.Column(db.String(100))
    secret = db.Column(db.String(100))
    port = db.Column(db.String(100))
    location = db.Column(db.String(100))
    group = db.Column(db.String(100))

    def __init__(self, ip, username, password,secret,port,location,group):

        self.ip = ip
        self.username = username
        self.password = password
        self.secret = secret
        self.port = port
        self.location = location
        self.group = group
db.create_all()


# /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
@app.route('/')
def home():
    all_data = Data.query.all()

    return render_template("home.html", employees=all_data)

@app.route('/config', methods=['GET', 'POST'])
def config():
       p=[]
       ip=request.form.get('ip')
       username = request.form.get('username')
       password = request.form.get('password')
       secret =  request.form.get('secret')
       port = request.form.get('port')
       location=request.form.get('location')

       devices = {
           'device_type': location,
           'ip': ip,
           'username': username,
           'password': password,
           'secret': secret,
           'port': port }
       try:
           net_connect = ConnectHandler(**devices)
           net_connect.enable()
       except NetMikoTimeoutException:
           p.append(ip + " Device not reachable ")
           print(ip + ' Device not reachable.')

       except AuthenticationException:
           p.append(" Authentication Failure. ")
           print(' Authentication Failure.')

       except SSHException:
           p.append(" Make sure SSH is enabled in device. ")
           print(' Make sure SSH is enabled in device.')


       p.append(ip + " Device Successfully Connected ")
       if location=='juniper_junos':
          print(location)
          ios_output = net_connect.send_command('show configuration')
          ios_output1 = net_connect.send_command('')
          ios_output2 = net_connect.send_command('')
          ios_output3 = net_connect.send_command('')
          session['feedback'] = ios_output
          session['feedback1'] = ios_output1
          session['feedback2'] = ios_output2
          session['feedback3'] = ios_output3
          net_connect.disconnect()
       elif location=='cisco_ios':
           print(location)
           ios_output = net_connect.send_command('show ip interface brief')
           ios_output1 = net_connect.send_command('show ip arp')
           ios_output2 = net_connect.send_command('show ip interface')
           ios_output3 = net_connect.send_command('show ip route')
           session['feedback'] = ios_output
           session['feedback1'] = ios_output1
           session['feedback2'] = ios_output2
           session['feedback3'] = ios_output3
           net_connect.disconnect()




       return render_template('config.html',p=p)

# /////////////////////////////////////////////////////////////////////////////////////////////////////////////////

# This is the index route where we are going to
# query on all our employee data
@app.route('/Index')
def Index():
    all_data = Data.query.all()

    return render_template("index.html", employees=all_data)


# this route is for inserting data to mysql database via html forms
@app.route('/insert', methods=['POST'])
def insert():
    if request.method == 'POST':
        ip = request.form['ip']
        username = request.form['username']
        password = request.form['password']
        secret = request.form['secret']
        port = request.form['port']
        location = request.form['location']
        group = request.form['group']

        my_data = Data(ip, username, password,secret,port,location,group)
        db.session.add(my_data)
        db.session.commit()

        flash("Device Inserted Successfully")

        return redirect(url_for('Index'))


# this is our update route where we are going to update our employee
@app.route('/update', methods=['GET', 'POST'])
def update():
    if request.method == 'POST':
        my_data = Data.query.get(request.form.get('id'))

        my_data.ip = request.form['ip']
        my_data.username = request.form['username']
        my_data.password = request.form['password']
        my_data.secret = request.form['secret']
        my_data.port = request.form['port']
        my_data.location = request.form['location']
        my_data.group = request.form['group']

        db.session.commit()
        flash("Device Updated Successfully")

        return redirect(url_for('Index'))


# This route is for deleting our employee
@app.route('/delete/<id>/', methods=['GET', 'POST'])
def delete(id):
    my_data = Data.query.get(id)
    db.session.delete(my_data)
    db.session.commit()
    flash("Device Deleted Successfully")

    return redirect(url_for('Index'))

#///////////////////////////////////////////////////////////////////
class Infoform(FlaskForm):
    ipaddress = StringField('IPAddress:',validators=[DataRequired()])
    username = StringField('UserName:', validators=[DataRequired()])
    password = PasswordField('Password:', validators=[DataRequired()])
    port = StringField('Port:')
    feedback = TextAreaField()
    submit = SubmitField('Info')


@app.route('/index1', methods=['GET','POST'])
def index1():
    try:
        p = []
        ip = request.form.get('ip')
        print(ip)
        p.append("IP Enter is "+ip)

        net4 = ipaddress.ip_network(ip)
        p.append("Prefix is :")
        p.append(net4.prefixlen )
        p.append("Subnetmask is :")
        p.append(net4.netmask)
        p.append("Total IPs is :")
        p.append(net4.num_addresses)
        p.append("Broadcast is :")
        p.append(net4.broadcast_address)
        p.append("First SubNetwork :")
        for x in net4.subnets():
           p.append(x)


    except:
        print("No")

    return render_template('index1.html', len=len(p), p=p)


#//////////////////////////////////////////////////////////////////



#///////////////////////////////Automation///////////////////////////////////
@app.route('/automate', methods = ['GET', 'POST'])
def automate():
    p=[]
    g=request.form.get('group1')
    all_data = Data.query.filter_by(group=g)

    c = request.form.get('config')
    all_config = Data.query.filter_by(group=c)
    for record in all_config:
        devices = {
            'device_type': record.location,
            'ip': record.ip,
            'username': record.username,
            'password': record.password,
            'secret': record.secret,
            'port': record.port
        }

        try:
            net_connect = ConnectHandler(**devices)
            net_connect.enable()
        except NetMikoTimeoutException:
                p.append(record.ip+" Device not reachable ")
                print(record.ip+' Device not reachable.')
                continue
        except AuthenticationException:
                p.append(record.ip + " Authentication Failure. ")
                print(record.ip+' Authentication Failure.')
                continue
        except SSHException:
                p.append(record.ip + " Make sure SSH is enabled in device. ")
                print(record.ip+' Make sure SSH is enabled in device.')
                continue

        p.append(record.ip + " Device Successfully Connected ")
        output = net_connect.send_config_from_file(config_file='configurationfile')
        print(output)
        p.append(record.ip + " Device Successfully Updated")
        net_connect.disconnect()

    return render_template('automate.html', all_data= all_data, len=len(p), p=p)
#///////////////////////////////////BackupConfig///////////////////
@app.route('/backup', methods = ['GET', 'POST'])
def backup():
    p=[]
    command = request.form.get('command')
    b = request.form.get('backup')
    all_backup = Data.query.filter_by(group=b)
    TNOW = datetime.now().replace(microsecond=0)
    for record in all_backup:
        devices = {
            'device_type': record.location,
            'ip': record.ip,
            'username': record.username,
            'password': record.password,
            'secret': record.secret,
            'port': record.port
        }

        try:
            net_connect = ConnectHandler(**devices)
            net_connect.enable()
        except NetMikoTimeoutException:
            print(record.ip + ' Device not reachable.')
            p.append(record.ip + ' Device not reachable.')
            continue
        except AuthenticationException:
            print(record.ip + ' Authentication Failure.')
            p.append(record.ip + ' Authentication Failure.')
            continue
        except SSHException:
            print(record.ip + ' Make sure SSH is enabled in device.')
            p.append(record.ip + ' Make sure SSH is enabled in device.')
            continue

        print(record.ip + ' Initiating cofig backup at ' + str(TNOW))
        p.append(record.ip + ' Initiating cofig backup at ' + str(TNOW))
        output = net_connect.send_command(command)#show run

        SAVE_FILE = open("Backup_ " + record.ip+".txt" , 'w')
        SAVE_FILE.write(output)
        SAVE_FILE.close
        print(record.ip + ' Finished config backup')
        p.append(record.ip + ' Finished config backup')
    return render_template('backup.html', len=len(p), p=p)


#///////////////////////////////////////////////////////////////////
#/////////////////////////////////// IP FINDER //////////////////////
import ipapi
@app.route('/ipfinder', methods = ['GET', 'POST'])
def ipfinder():
    data=[]
    try:
        data = ipapi.location(ip=request.form.get('search'), output='json')
        print(data)
    except:
        print('Not valid')
    return render_template('ipfinder.html', data=data)

#////////////////////////////////////////////////////////////////////

#/////////////////////////SaveShowCommandOutPut/////////////////////////
@app.route('/saveshowcommand', methods=['GET', 'POST'])
def saveshowcommand():
    p=[]
    b = request.form.get('id')
    command=request.form.get('command')
    all_backup = Data.query.filter_by(id=b)
    TNOW = datetime.now().replace(microsecond=0)
    for record in all_backup:
        devices = {
            'device_type': record.location,
            'ip': record.ip,
            'username': record.username,
            'password': record.password,
            'secret': record.secret,
            'port': record.port
        }

        try:
            net_connect = ConnectHandler(**devices)
            net_connect.enable()
        except NetMikoTimeoutException:
            p.append(record.ip + ' Device not reachable.')
            print(record.ip + ' Device not reachable.')
            continue
        except AuthenticationException:
            p.append(record.ip + ' Authentication Failure.')
            print(record.ip + ' Authentication Failure.')
            continue
        except SSHException:
            p.append(record.ip + ' Make sure SSH is enabled in device.')
            print(record.ip + ' Make sure SSH is enabled in device.')
            continue

        print(record.ip + ' Initiating Saving Show Command at ' + str(TNOW))
        p.append(record.ip + ' Initiating Saving Show Command at ' + str(TNOW))
        output = net_connect.send_command(command)
        net_connect.disconnect()

        SAVE_FILE = open("Show_ " + record.ip + ".txt", 'w')
        SAVE_FILE.write(output)
        SAVE_FILE.close()
        print(record.ip + ' Finished Show Command Saving')
        p.append(record.ip + ' Finished Show Command Saving')
    return render_template('saveshowcommand.html', len=len(p), p=p)


#//////////////////////////////////////////////////////////////////////

#///////////////////////////////SaveRunningConfig///////////////////////////////////
@app.route('/configsave', methods = ['GET', 'POST'])
def configsave():
    p=[]
    command=request.form.get('command')
    c = request.form.get('group')
    all_config = Data.query.filter_by(group=c)
    for record in all_config:
        devices = {
            'device_type': record.location,
            'ip': record.ip,
            'username': record.username,
            'password': record.password,
            'secret': record.secret,
            'port': record.port
        }

        try:
            net_connect = ConnectHandler(**devices)
            net_connect.enable()
        except NetMikoTimeoutException:
                p.append(record.ip+" Device not reachable ")
                print(record.ip+' Device not reachable.')
                continue
        except AuthenticationException:
                p.append(record.ip + " Authentication Failure. ")
                print(record.ip+' Authentication Failure.')
                continue
        except SSHException:
                p.append(record.ip + " Make sure SSH is enabled in device. ")
                print(record.ip+' Make sure SSH is enabled in device.')
                continue
        p.append(record.ip + ' Saving Config To Startup')
        print(record.ip + ' Saving Config To Startup')
        output = net_connect.save_config(command)#'write mem'

        print(output)

        net_connect.disconnect()

    return render_template('configsave.html', len = len(p), p = p)
#////////////////////////////////////////Graph/////////////////////////////////////////////

@app.route('/dash',  methods=['GET', 'POST'])

def dash():

    d=[]
    e=[]
    f=[]
    g=[]
    h=[]
    i=[]
    type=[]
    z=''
    ip = request.form.get('ip')
    username = request.form.get('username')
    password = request.form.get('password')
    secret = request.form.get('secret')
    port = request.form.get('port')
    location = request.form.get('location')
    if location == 'cisco_ios':
        type = 'ios'
    elif location == 'Juniper_Junos':
        type = 'junos'

    driver = get_network_driver(type)

    device = driver(ip, username, password,
                    optional_args={"port": port, "secret": secret})

    device.open()
    print(ip)


    try:
        device.open()
        print(ip)

    except NetMikoTimeoutException:

          print(ip + ' Device not reachable.')

    except AuthenticationException:

           print(' Authentication Failure.')

    except SSHException:

           print(' Make sure SSH is enabled in device.')
    try:
      ios_output = device.get_environment()
      a = ios_output['memory']['used_ram']
      b = ios_output['memory']['available_ram']

      c = round(100.0 * a / b, 2)
      print(c)
      i = ios_output['cpu'][0]['%usage']
      ios_output1 = device.get_facts()
      d = (round(ios_output1['uptime'] / 3600, 2))
      e = (ios_output1['hostname'])
      f = (ios_output1['vendor'])
      g = (ios_output1['interface_list'])
      ios_output2 = device.get_interfaces_counters()
      out1 = device.is_alive()
      print(out1)
      if out1['is_alive'] == True:
        print("UP")
        h = "UP"
      else:
        print("Down")
        h = "Down"
    except:
        z="Notable To Fetch "

    return render_template('dash.html', c=c, d=d, e=e, f=f, g=g, h=h, i=i,ip=ip,location=location,z=z,ios_output2=ios_output2)


"""
@app.route('/chart_data')
def chart_data():



    driver = get_network_driver('ios')

    device = driver('192.168.18.87', 'cisco', 'cisco',
                    optional_args={"port": '22', "secret": 'cisco'})

    device.open()

    def generate_random_data():
        while True:
            ios_output = device.get_environment()
            output = ios_output['cpu'][0]['%usage']
            print(output)

            json_data = json.dumps(
                {'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'value': output})
            yield f"data:{json_data}\n\n"
            time.sleep(1)

    return Response(generate_random_data(), mimetype='text/event-stream')
"""

#/////////////////////////////////////////////////////////////////////////////////////////

#//////////////////////////////////////Traceroute////////////////////////////////////////
@app.route('/trace' , methods = ['GET', 'POST'])
def trace():

        ip=request.form.get('ip')
        print(ip)
        os.replace("./static/traceroute_graph.svg","./static/traceroute_graph1.svg")
        res,unans = traceroute(ip)
        res.graph(target=">./static/traceroute_graph.svg")



        return render_template('traceroute.html')

#///////////////////////////////////////////////////////////////////////////////////////

#///////////////////////////////Devicevalue////////////////////////////////////////////
@app.route('/devicevalue' , methods = ['GET', 'POST'])
def devicevalue():
    os=request.form.get('location')
    ip = request.form.get('ip')
    username = request.form.get('username')
    password = request.form.get('password')
    secret = request.form.get('secret')
    port = request.form.get('port')
    if os == 'cisco_ios':
        type = 'ios'
    elif os == 'Juniper_Junos':
        type = 'junos'
    driver = get_network_driver(type)
    device = driver(ip, username, password,
                    optional_args={"port": port, "secret": secret})


    try:
        device.open()
        print(ip)
    except NetMikoTimeoutException:
          print(ip + ' Device not reachable.')
    except AuthenticationException:
           print(' Authentication Failure.')
    except SSHException:
           print(' Make sure SSH is enabled in device.')

    ios_output = device.get_facts()

    ios_output1=device.get_arp_table()
    print(ios_output1)
    ios_output2=device.get_interfaces_counters()





    return render_template('devicevalue.html',os=os,ip=ip,username=username,password=password,secret=secret,port=port,ios_output2=ios_output2,ios_output1=ios_output1)
#/////////////////////////////////////////////////////////////////////////////////////

if __name__ == "__main__":
    app.run(debug=True )