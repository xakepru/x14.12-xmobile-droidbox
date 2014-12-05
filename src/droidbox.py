# ###############################################################################
# (c) 2011, The Honeynet Project
# Author: Patrik Lantz patrik@pjlantz.com and Laurent Delosieres ldelosieres@hispasec.com
#
# This program is free software you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#
################################################################################

"""Analyze dynamically Android applications

This script allows you to analyze dynamically Android applications. It installs, runs, and analyzes Android applications.
At the end of each analysis, it outputs the Android application's characteristics in JSON.
Please keep in mind that all data received/sent, read/written are shown in hexadecimal since the handled data can contain binary data.
"""

import sys, json, time, curses, signal, os, inspect
import zipfile, StringIO
import tempfile, shutil
import operator
import subprocess
import thread, threading
import re

from threading import Thread
from xml.dom import minidom
from subprocess import call, PIPE, Popen
from utils import AXMLPrinter
import hashlib
from pylab import *
import matplotlib
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle
from matplotlib.font_manager import FontProperties

from collections import OrderedDict

sendsms = {}
phonecalls = {}
cryptousage = {}
dexclass = {}
dataleaks = {}
opennet = {}
sendnet = {}
recvnet = {}
closenet = {}
fdaccess = {}
servicestart = {}
accessedfiles = {}
timestr = time.strftime("%Y%m%d-%H%M")

tags = {0x1: "TAINT_LOCATION", 0x2: "TAINT_CONTACTS", 0x4: "TAINT_MIC", 0x8: "TAINT_PHONE_NUMBER",
        0x10: "TAINT_LOCATION_GPS", 0x20: "TAINT_LOCATION_NET", 0x40: "TAINT_LOCATION_LAST", 0x80: "TAINT_CAMERA",
        0x100: "TAINT_ACCELEROMETER", 0x200: "TAINT_SMS", 0x400: "TAINT_IMEI", 0x800: "TAINT_IMSI",
        0x1000: "TAINT_ICCID", 0x2000: "TAINT_DEVICE_SN", 0x4000: "TAINT_ACCOUNT", 0x8000: "TAINT_BROWSER",
        0x10000: "TAINT_OTHERDB", 0x20000: "TAINT_FILECONTENT", 0x40000: "TAINT_PACKAGE", 0x80000: "TAINT_CALL_LOG",
        0x100000: "TAINT_EMAIL", 0x200000: "TAINT_CALENDAR", 0x400000: "TAINT_SETTINGS"}


class CountingThread(Thread):
    """
    Used for user interface, showing in progress sign
    and number of collected logs from the sandbox system
    """

    def __init__(self):
        """
        Constructor
        """

        Thread.__init__(self)
        self.stop = False
        self.logs = 0

    def stopCounting(self):
        """
        Mark to stop this thread
        """

        self.stop = True

    def increaseCount(self):

        self.logs = self.logs + 1

    def run(self):
        """
        Update the progress sign and
        number of collected logs
        """

        signs = ['|', '/', '-', '\\']
        counter = 0
        while 1:
            sign = signs[counter % len(signs)]
            sys.stdout.write("     \033[132m[%s] Collected %s sandbox logs\033[1m   (Ctrl-C to view logs)\r" % (
            sign, str(self.logs)))
            sys.stdout.flush()
            time.sleep(0.5)
            counter = counter + 1
            if self.stop:
                sys.stdout.write(
                    "   \033[132m[%s] Collected %s sandbox logs\033[1m%s\r" % ('*', str(self.logs), ' ' * 25))
                sys.stdout.flush()
                break


class Application:
    """
    Used for extracting information of an Android APK
    """

    def __init__(self, filename):
        self.filename = filename
        self.packageNames = []
        self.enfperm = []
        self.permissions = []
        self.recvs = []
        self.activities = {}
        self.recvsaction = {}

        self.mainActivity = None

    def processAPK(self):
        xml = {}
        error = True
        try:
            zip = zipfile.ZipFile(self.filename)

            for i in zip.namelist():
                if i == "AndroidManifest.xml":
                    try:
                        xml[i] = minidom.parseString(zip.read(i))
                    except:
                        xml[i] = minidom.parseString(AXMLPrinter(zip.read(i)).getBuff())

                    for item in xml[i].getElementsByTagName('manifest'):
                        self.packageNames.append(str(item.getAttribute("package")))

                    for item in xml[i].getElementsByTagName('permission'):
                        self.enfperm.append(str(item.getAttribute("android:name")))

                    for item in xml[i].getElementsByTagName('uses-permission'):
                        self.permissions.append(str(item.getAttribute("android:name")))

                    for item in xml[i].getElementsByTagName('receiver'):
                        self.recvs.append(str(item.getAttribute("android:name")))
                        for child in item.getElementsByTagName('action'):
                            self.recvsaction[str(item.getAttribute("android:name"))] = (
                            str(child.getAttribute("android:name")))

                    for item in xml[i].getElementsByTagName('activity'):
                        activity = str(item.getAttribute("android:name"))
                        self.activities[activity] = {}
                        self.activities[activity]["actions"] = list()

                        for child in item.getElementsByTagName('action'):
                            self.activities[activity]["actions"].append(str(child.getAttribute("android:name")))

                    for activity in self.activities:
                        for action in self.activities[activity]["actions"]:
                            if action == 'android.intent.action.MAIN':
                                self.mainActivity = activity
                    error = False

                    break

            if (error == False):
                return 1
            else:
                return 0

        except:
            return 0

    def getEnfperm(self):
        return self.enfperm

    def getRecvsaction(self):
        return self.recvsaction

    def getMainActivity(self):
        return self.mainActivity

    def getActivities(self):
        return self.activities

    def getRecvActions(self):
        return self.recvsaction

    def getPackage(self):
        #One application has only one package name
        return self.packageNames[0]

    def getHashes(self, block_size=2 ** 8):
        """
        Calculate MD5,SHA-1, SHA-256
        hashes of APK input file
        """

        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        f = open(self.filename, 'rb')
        while True:
            data = f.read(block_size)
            if not data:
                break

            md5.update(data)
            sha1.update(data)
            sha256.update(data)
        return [md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()]


def decode(s, encodings=('ascii', 'utf8', 'latin1')):
    for encoding in encodings:
        try:
            return s.decode(encoding)
        except UnicodeDecodeError:
            pass
    return s.decode('ascii', 'ignore')


def getTags(tagParam):
    """
    Retrieve the tag names
    """

    tagsFound = []
    for tag in tags.keys():
        if tagParam & tag != 0:
            tagsFound.append(tags[tag])
    return tagsFound


def hexToStr(hexStr):
    """
    Convert a string hex byte values into a byte string
    """

    bytes = []
    hexStr = ''.join(hexStr.split(" "))
    for i in range(0, len(hexStr), 2):
        bytes.append(chr(int(hexStr[i:i + 2], 16)))
    return unicode(''.join(bytes), errors='replace')


def interruptHandler(signum, frame):
    """
	Raise interrupt for the blocking call 'logcatInput = sys.stdin.readline()'
	
	"""
    raise KeyboardInterrupt


def main(argv):
    if len(argv) < 2 or len(argv) > 3:
        print("Usage: droidbox.py filename.apk <duration in seconds>")
        sys.exit(1)

    duration = 0

    #Duration given?
    if len(argv) == 3:
        duration = int(argv[2])

    apkName = sys.argv[1]

    #APK existing?
    if os.path.isfile(apkName) == False:
        print("File %s not found" % argv[1])
        sys.exit(1)

    application = Application(apkName)
    ret = application.processAPK()

    #Error during the APK processing?
    if (ret == 0):
        print("Failed to analyze the APK. Terminate the analysis.")
        sys.exit(1)

    activities = application.getActivities()
    mainActivity = application.getMainActivity()
    packageName = application.getPackage()

    recvsaction = application.getRecvsaction()
    enfperm = application.getEnfperm()

    #Get the hashes
    hashes = application.getHashes()

    # in PyCharm the next two lines does not work
    curses.setupterm()
    sys.stdout.write(curses.tigetstr("clear"))
    sys.stdout.flush()
    call(['adb', 'logcat', '-c'])

    print " ____                        __  ____"
    print "/\  _`\               __    /\ \/\  _`\\"
    print "\ \ \/\ \  _ __  ___ /\_\   \_\ \ \ \L\ \   ___   __  _"
    print " \ \ \ \ \/\`'__\ __`\/\ \  /'_` \ \  _ <' / __`\/\ \/'\\"
    print "  \ \ \_\ \ \ \/\ \L\ \ \ \/\ \L\ \ \ \L\ \\ \L\ \/>  </"
    print "   \ \____/\ \_\ \____/\ \_\ \___,_\ \____/ \____//\_/\_\\"
    print "    \/___/  \/_/\/___/  \/_/\/__,_ /\/___/ \/___/ \//\/_/"

    #No Main acitvity found? Return an error
    if mainActivity == None:
        print("No activity to start. Terminate the analysis.")
        sys.exit(1)

    #No packages identified? Return an error
    if packageName == None:
        print("No package found. Terminate the analysis.")
        sys.exit(1)

    #Execute the application
    ret = call(['monkeyrunner', 'monkeyrunner.py', apkName, packageName, mainActivity], stderr=PIPE,
               cwd=os.path.dirname(os.path.realpath(__file__)))

    if (ret == 1):
        print("Failed to execute the application.")
        sys.exit(1)

    print("Starting the activity %s..." % mainActivity)

    #By default the application has not started
    applicationStarted = 0
    stringApplicationStarted = "Start proc %s" % packageName

    #Open the adb logcat
    adb = Popen(["adb", "logcat", "DroidBox:W", "dalvikvm:W", "ActivityManager:I"], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE)

    #Wait for the application to start
    while 1:
        try:
            logcatInput = adb.stdout.readline()
            if not logcatInput:
                raise Exception("We have lost the connection with ADB.")

            #Application started?
            if (stringApplicationStarted in logcatInput):
                applicationStarted = 1
                break;
        except:
            break

    if (applicationStarted == 0):
        print("Analysis has not been done.")
        #Kill ADB, otherwise it will never terminate
        os.kill(adb.pid, signal.SIGTERM)
        sys.exit(1)

    print("Application started")
    print("Analyzing the application during %s seconds..." % (duration if (duration != 0) else "infinite time"))

    count = CountingThread()
    count.start()

    timeStamp = time.time()
    if duration:
        signal.signal(signal.SIGALRM, interruptHandler)
        signal.alarm(duration)

    #Collect DroidBox logs
    while 1:
        try:
            logcatInput = adb.stdout.readline()
            if not logcatInput:
                raise Exception("We have lost the connection with ADB.")

            boxlog = logcatInput.split('DroidBox:')
            if len(boxlog) > 1:
                try:
                    load = json.loads(decode(boxlog[1]))

                    # DexClassLoader
                    if load.has_key('DexClassLoader'):
                        load['DexClassLoader']['type'] = 'dexload'
                        dexclass[time.time() - timeStamp] = load['DexClassLoader']
                        count.increaseCount()

                    # service started
                    if load.has_key('ServiceStart'):
                        load['ServiceStart']['type'] = 'service'
                        servicestart[time.time() - timeStamp] = load['ServiceStart']
                        count.increaseCount()

                    # received data from net
                    if load.has_key('RecvNet'):
                        host = load['RecvNet']['srchost']
                        port = load['RecvNet']['srcport']

                        recvnet[time.time() - timeStamp] = recvdata = {'type': 'net read', 'host': host, 'port': port,
                                                                       'data': load['RecvNet']['data']}
                        count.increaseCount()

                    # fdaccess
                    if load.has_key('FdAccess'):
                        accessedfiles[load['FdAccess']['id']] = hexToStr(load['FdAccess']['path'])

                    # file read or write
                    if load.has_key('FileRW'):
                        load['FileRW']['path'] = accessedfiles[load['FileRW']['id']]
                        if load['FileRW']['operation'] == 'write':
                            load['FileRW']['type'] = 'file write'
                        else:
                            load['FileRW']['type'] = 'file read'

                        fdaccess[time.time() - timeStamp] = load['FileRW']
                        count.increaseCount()

                    # opened network connection log
                    if load.has_key('OpenNet'):
                        load['OpenNet']['type'] = 'net open'
                        opennet[time.time() - timeStamp] = load['OpenNet']
                        count.increaseCount()

                    # closed socket
                    if load.has_key('CloseNet'):
                        load['CloseNet']['type'] = "net close"
                        closenet[time.time() - timeStamp] = load['CloseNet']
                        count.increaseCount()

                    # outgoing network activity log
                    if load.has_key('SendNet'):
                        load['SendNet']['type'] = 'net write'
                        sendnet[time.time() - timeStamp] = load['SendNet']

                        count.increaseCount()

                    # data leak log
                    if load.has_key('DataLeak'):
                        my_time = time.time() - timeStamp
                        load['DataLeak']['type'] = 'leak'
                        load['DataLeak']['tag'] = getTags(int(load['DataLeak']['tag'], 16))
                        dataleaks[my_time] = load['DataLeak']
                        count.increaseCount()

                        if load['DataLeak']['sink'] == 'Network':
                            load['DataLeak']['type'] = 'net write'
                            sendnet[my_time] = load['DataLeak']
                            count.increaseCount()

                        elif load['DataLeak']['sink'] == 'File':
                            load['DataLeak']['path'] = accessedfiles[load['DataLeak']['id']]
                            if load['DataLeak']['operation'] == 'write':
                                load['DataLeak']['type'] = 'file write'
                            else:
                                load['DataLeak']['type'] = 'file read'

                            fdaccess[my_time] = load['DataLeak']
                            count.increaseCount()

                        elif load['DataLeak']['sink'] == 'SMS':
                            load['DataLeak']['type'] = 'sms'
                            sendsms[my_time] = load['DataLeak']
                            count.increaseCount()

                        # sent sms log
                    if load.has_key('SendSMS'):
                        load['SendSMS']['type'] = 'sms'
                        sendsms[time.time() - timeStamp] = load['SendSMS']
                        count.increaseCount()

                    # phone call log
                    if load.has_key('PhoneCall'):
                        load['PhoneCall']['type'] = 'call'
                        phonecalls[time.time() - timeStamp] = load['PhoneCall']
                        count.increaseCount()

                    # crypto api usage log
                    if load.has_key('CryptoUsage'):
                        load['CryptoUsage']['type'] = 'crypto'
                        cryptousage[time.time() - timeStamp] = load['CryptoUsage']
                        count.increaseCount()
                except ValueError:
                    pass

        except:
            try:
                count.stopCounting()
                count.join()
            finally:
                break;

    #Kill ADB, otherwise it will never terminate
    os.kill(adb.pid, signal.SIGTERM)

    #Done? Store the objects in a dictionary, transform it in a JSON object and return it
    output = dict()

    #Sort the items by their key
    output["dexclass"] = dexclass
    output["servicestart"] = servicestart

    output["recvnet"] = recvnet
    output["opennet"] = opennet
    output["sendnet"] = sendnet
    output["closenet"] = closenet

    output["accessedfiles"] = accessedfiles
    output["dataleaks"] = dataleaks

    output["fdaccess"] = fdaccess
    output["sendsms"] = sendsms
    output["phonecalls"] = phonecalls
    output["cryptousage"] = cryptousage

    output["recvsaction"] = recvsaction
    output["enfperm"] = enfperm

    output["hashes"] = hashes
    output["apkName"] = apkName

    print(json.dumps(output))


    # generate behavior image (from svn extrenal/droidbox.py)

    ###################################################
    def createBehImg():
        labels = {'begin': 0, 'dexload': 1, 'service': 2, 'call': 3, 'sms': 4,
                  'leak': 5, 'file read': 6, 'file write': 7,
                  'net open': 8, 'net read': 9, 'net write': 10,
                  'crypto': 11, 'end': 12}

        result = list()
        predict = list()
        mergedLogs = dict(dexclass.items() + servicestart.items() + phonecalls.items() + sendsms.items() + recvnet.items() +
                          dataleaks.items() + cryptousage.items() + opennet.items() + sendnet.items() + fdaccess.items()) # opennet deletion: cryptousage.items() + opennet.items() + sendnet.items() UPD: fixed
        keys = mergedLogs.keys()
        keys.sort()
        for key in keys:
            result.append(key)
            temp = mergedLogs[key]
            predict.append(labels[temp['type']])

        ax = gca()
        ax.plot(result, predict, c='r', marker='o', linewidth=2)
        ax.set_yticks((0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12))

        # Add y-axis labes
        ylabels = []
        for key, value in sorted(labels.iteritems(), key=lambda (k, v): (v, k)):
            if key == 'begin' or key == 'end':
                key = ''
            ylabels.append(key)
        ax.set_yticklabels(ylabels)

        # Create zebra stripes on y-axis
        yTickPos, _ = plt.yticks()
        yTickPos = yTickPos[:-1]
        ax.barh(yTickPos, [60] * len(yTickPos), height=(yTickPos[1] - yTickPos[0]), color=['#FFFFCC', 'w'], linewidth=0.0)
        grid(True)

        xlabel('timestamp', {'fontsize': 18})
        ylabel('activity', {'fontsize': 18})
        try:
            ax.set_xlim(0, 60)  #result[len(result)-1])
        except:
            sys.exit(1)

        # Save figure
        title(apkName)
        F = gcf()
        DefaultSize = F.get_size_inches()
        F.set_size_inches((DefaultSize[0] * 1.2, DefaultSize[1] * 1.2))
        Size = F.get_size_inches()
        savefig("behaviorgraph-" + packageName + "-" + timestr + ".png")
        print "\n\nSaved APK behavior graph as: behaviorgraph-" + packageName + "-" + timestr + ".png\n"
        plt.clf()

############################################


# generate tree map (from svn extrenal/droidbox.py)
############################################
    def createTreeMap():

        # Generate treemap
        NODE_CHILDREN = ['DEXLOAD', 'SERVICE', 'CALL', 'SMSSEND', 'SMSLEAK', 'FILEWRITE', 'FILEREAD', 'FILELEAK',
                         'NETOPEN', 'NETWRITE', 'NETREAD', 'NETLEAK', 'CRYPTKEY', 'CRYPTDEC', 'CRYPTENC']
        MAP_COLORS = {'DEXLOAD': '#008080', 'SERVICE': '#00ffff', 'CALL': "#66cdaa", 'SMSSEND': "#8fbc8f",
                      'SMSLEAK': '#2e8b57', 'FILEWRITE': '#ffd700',
                      'FILEREAD': '#eedd82', 'FILELEAK': '#daa520', 'NETOPEN': '#c80000', 'NETWRITE': '#cd5c5c',
                      'NETREAD': '#bc8f8f', 'NETLEAK': '#8b4513', 'CRYPTKEY': '#6495ed', 'CRYPTDEC': '#483d8b',
                      'CRYPTENC': '#6a5acd'}

        class Treemap:

            def __init__(self, tree, iter_method, size_method, color_method):
                """
                Create a tree map from tree, using itermethod(node) to walk tree,
                size_method(node) to get object size and color_method(node) to get its
                color
                """

                self.ax = gca()
                subplots_adjust(left=0, right=1, top=1, bottom=0)
                self.ax.set_xticks([])
                self.ax.set_yticks([])
                self.treemapIter = 0

                self.size_method = size_method
                self.iter_method = iter_method
                self.color_method = color_method
                self.tree = tree
                self.addnode(tree)

                # Legend box
                box = self.ax.get_position()
                self.ax.set_position([box.x0, box.y0, box.width * 0.8, box.height])
                self.ax.legend(loc='upper center', bbox_to_anchor=(0.5, -0.05),
                               fancybox=True, shadow=True, ncol=5)

            def addnode(self, node, lower=[0,0], upper=[1,1], axis=0):
                axis = axis % 2
                self.draw_rectangle(lower, upper, node)
                width = upper[axis] - lower[axis]
                if not isinstance(node, tuple):
                    self.treemapIter = self.treemapIter + 1
                try:
                    for child in self.iter_method(node):
                        if child != 0:
                            upper[axis] = lower[axis] + (width * float(size(child))) / size(node)
                            self.addnode(child, list(lower), list(upper), axis + 1)
                            lower[axis] = upper[axis]
                        else:
                            self.treemapIter = self.treemapIter + 1
                except TypeError:
                    pass
                except ZeroDivisionError:
                    pass

            def draw_rectangle(self, lower, upper, node):
                if not isinstance(node, tuple):
                    r = Rectangle(lower, upper[0]-lower[0], upper[1] - lower[1],
                                  edgecolor='k', linewidth=0.3,
                                  facecolor= self.color_method(node, self.treemapIter),
                                  label=NODE_CHILDREN[self.treemapIter])
                    self.ax.add_patch(r)

        size_cache = {}
        def size(thing):
            if isinstance(thing, int):
                return thing
            if thing in size_cache:
                return size_cache[thing]
            else:
                size_cache[thing] = reduce(int.__add__, [size(x) for x in thing])
                return size_cache[thing]
        def set_color(thing, iternbr):
            return MAP_COLORS[NODE_CHILDREN[iternbr]]

        tree = list()
        # get started services and class loads
        dexloadservice = list()
        dexloads = len(dexclass)
        dexloadservice.append(dexloads)
        services = len(servicestart)
        dexloadservice.append(services)
        tree.append(tuple(dexloadservice))

        # get phone call actions
        calls = len(phonecalls)
        tree.append(calls)
        # get sms actions
        sms = list()
        smssend = len(sendsms)
        sms.append(smssend)
        count = 0
        for k, v in dataleaks.items():
            if v['sink'] == 'SMS':
                count = count + 1
        sms.append(count)
        tree.append(tuple(sms))
        # get file operations
        file = list()
        countw = 0
        countr = 0
        for k,v in fdaccess.items():
            if v['operation'] == 'read':
                countr = countr + 1
            else:
                countw = countw + 1
        file.append(countw)
        file.append(countr)
        count = 0
        for k,v in dataleaks.items():
            if v['sink'] == 'File':
                count = count + 1
        file.append(count)
        tree.append(tuple(file))
        # get network operations
        network = list()
        network.append(len(opennet))
        network.append(len(sendnet))
        network.append(len(recvnet))
        count = 0
        for k,v in dataleaks.items():
            if v['sink'] == 'Network':
                count = count + 1
        network.append(count)
        tree.append(tuple(network))
        # get crypto operations
        crypto = list()
        countk = 0
        countd = 0
        counte = 0
        for k,v in cryptousage.items():
            if v['operation'] == 'keyalgo':
                countk = countk + 1
            if v['operation'] == 'encryption':
                counte = counte + 1
            if v['operation'] == 'decryption':
                countd = countd + 1
        crypto.append(countk)
        crypto.append(countd)
        crypto.append(counte)
        tree.append(tuple(crypto))
        tree = tuple(tree)
        Treemap(tree, iter, size, set_color)
        xlabel('section', {'fontsize': 18})
        ylabel('operation', {'fontsize': 18})
        title(apkName)
        F = gcf()
        DefaultSize = F.get_size_inches()
        F.set_size_inches( (DefaultSize[0]*1.5, DefaultSize[1]*1.5))
        Size = F.get_size_inches()
        savefig('tree-' + packageName + "-" + timestr + '.png', bbox_inches = 'tight', pad_inches = 2.0)
        print "Saved treemap graph as: tree-"  + packageName + "-" + timestr + ".png\n"

############################################
    createBehImg()
    createTreeMap()
    # also save json output as a file
    with open("trace-" + packageName + "-" + timestr + ".json", "w") as jsonfile:
        jsonfile.write(json.dumps(output, sort_keys=True, indent=4))
    print "Saved trace as: trace-" + packageName + "-" + timestr + ".json"

    sys.exit(0)

if __name__ == "__main__":
    main(sys.argv)
