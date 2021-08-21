import pandas as pd
import keyconstants
import mitreattack
import os
import requests
import json
import datetime
pd.options.mode.chained_assignment = None  #avoid any warning in regards to dataframe in-copy 


class EventLogDB:
    """
    The class EventLogDB reads all the csv files from the directory 'Logs'
    Each log file was pulled from a device. Each row in the logs files represent a activity related to
    device process, file, network events. The EventLogDB parses each row and generates seperate dataframes for process,
    file and network events. It acts a Database repository which would be called upon by the Class Computer().

    """
    
    def __init__(self):
        self.computer_pds = []
        self.process_pds = []
        self.network_pds = []
        self.file_pds = []
        self.computerlist = []
        
        #Read all csv files from the folder 'Logs'
        for csv_file in os.listdir('Logs/'):
            if csv_file.endswith('.csv'):
                csv_file_path = 'Logs/' + csv_file
                try:
                    csv_pd = pd.read_csv(csv_file_path,low_memory=False)
                except:
                    raise Exception('csv file format Error, please make sure to have Microsoft Defender Endpoint logs in csv file in \logs folder')
                    
                if 'Timestamp' in csv_pd.columns and 'EventCategory' in csv_pd.columns and 'DeviceName' in csv_pd.columns:
                    csv_pd['Timestamp'] = pd.to_datetime(csv_pd['Timestamp']).apply(lambda x: x.replace(tzinfo=None))
                    csv_pd_deviceinfo = csv_pd[csv_pd['EventCategory'] == 'DeviceInfo']
                    self.computer_pds.append(csv_pd_deviceinfo.head(1))
                    csv_pd_deviceprocessevents = csv_pd[csv_pd['EventCategory'] == 'DeviceProcessEvents']
                    self.process_pds.append(csv_pd_deviceprocessevents)
                    csv_pd_devicenetworkevents = csv_pd[csv_pd['EventCategory'] == 'DeviceNetworkEvents']
                    self.network_pds.append(csv_pd_devicenetworkevents)
                    csv_pd_devicefileevents = csv_pd[csv_pd['EventCategory'] == 'DeviceFileEvents']
                    self.file_pds.append(csv_pd_devicefileevents)
                else:
                    raise Exception('csv file format Error, please make sure to have Microsoft Defender Endpoint logs in csv file in \logs folder')
            else:
                pass
        
        for computer_pd in self.computer_pds:
            #print(type(computer_pd['DeviceName'][0]))
            self.computerlist.append(computer_pd['DeviceName'].head(1).to_string(index=False).strip())
        
        
                
    
class Process(EventLogDB):

    """
    The class Process() parses through the log files for any process related events. It uses functions
    such as a process_activity() to look for all process events in the logs or process events from a 
    specific timeline depending on user input of start datetime and end datetime.
    
    """
    
    def __init__(self,eventlogdb,devicename,processname=None,start_datetime=None,end_datetime=None):
        self.eventlogdb = eventlogdb
        self.devicename = devicename
        self.startdatetime = start_datetime
        self.enddatetime = end_datetime
        self.processname = processname
        if self.processname != None:
            self.processname = self.processname.lower()
        
        if (self.startdatetime != None and self.enddatetime !=None):
            try:
                self.startdatetime = datetime.datetime.strptime(self.startdatetime,'%Y-%m-%d %H:%M')
                self.enddatetime = datetime.datetime.strptime(self.enddatetime,'%Y-%m-%d %H:%M')
                
            except ValueError:
                raise Exception('Wrong Format for DateTime, please enter the datetime as start_datetime = "YYY-MM-DD HH:MM",end_datetime="YYY-MM-DD HH:MM"')

        
    def process_activity(self):
        process_pds = self.eventlogdb.process_pds
        for p in process_pds:
            if p['DeviceName'].head(1).to_string(index=False).strip() == self.devicename:
                if self.startdatetime != None and self.enddatetime !=None:
                    self.mask = ((p['Timestamp'] > self.startdatetime) & (p['Timestamp'] < self.enddatetime))
                    p = p.loc[self.mask]
                    if self.processname != None:
                        p = p[(p['FileName'].str.contains(self.processname)) | (p['InitiatingProcessFileName'].str.contains(self.processname))]
                        if p.empty:
                            raise Exception("Please check the date/time process name you have entered, No result found")
                        else:
                            return p
                    else:
                        if p.empty:
                            raise Exception("Please check the Date/Time you have entered, No result found")
                        else:
                            return p
                    
                elif self.processname !=None:
                    #print("********I AM HERE ***********")
                    p = p[(p['FileName'].str.contains(self.processname)) | (p['InitiatingProcessFileName'].str.contains(self.processname))]
                    if p.empty:
                            raise Exception("Please check the process name you have entered, No result found")
                    else:
                        return p
                    
                else:
                    return p

            
class File(EventLogDB):

    """
    The class File() parses through the log files for any File related events. It uses functions
    such as a file_activity() to look for all file creation/deletion/modification events in the logs or file events from a 
    specific timeline depending on user input of start datetime and end datetime.
    
    """
    
    def __init__(self,eventlogdb,devicename,filename=None,start_datetime=None,end_datetime=None):
        self.devicename = devicename
        self.eventlogdb = eventlogdb
        self.startdatetime = start_datetime
        self.enddatetime = end_datetime
        self.filename=filename
        if self.filename !=None:
            self.filename = self.filename.lower()

        if (self.startdatetime != None and self.enddatetime !=None):
            try:
                self.startdatetime = datetime.datetime.strptime(self.startdatetime,'%Y-%m-%d %H:%M')
                self.enddatetime = datetime.datetime.strptime(self.enddatetime,'%Y-%m-%d %H:%M')
                
            except ValueError:
                raise Exception('Wrong Format for DateTime, please enter the datetime as start_datetime = "YYY-MM-DD HH:MM",end_datetime="YYY-MM-DD HH:MM"')

            
    def file_activity(self):
        for f in self.eventlogdb.file_pds:
            if f['DeviceName'].head(1).to_string(index=False).strip() == self.devicename:
                if self.startdatetime != None and self.enddatetime !=None:
                    self.mask = ((f['Timestamp'] > self.startdatetime) & (f['Timestamp'] < self.enddatetime))
                    f = f.loc[self.mask]
                    if self.filename != None:
                        f = f[f['FileName'].str.contains(self.filename)]
                        if f.empty:
                            raise Exception("Please check the Date/Time you have entered, No result found")
                        else:
                            return f
                    else:
                        if f.empty:
                            raise Exception("Please check the Date/Time you have entered, No result found")
                        else:
                            return f
                    
                elif self.filename !=None:
                    #print("********I AM HERE ***********")
                    f = f[f['FileName'].str.contains(self.filename)]
                    if f.empty:
                            raise Exception("Please check the filename you have entered, No result found")
                    else:
                        return f
                    
                else:
                    return f


class ThreatIntelligence:
    """
    The ThreatIntelligene Class is to be used when you want to use tools such as Virus Total to identify if a
    specific process or file is malicious or not. You will pass a MD5, SHA1 or SHA256 value to the VirusTotal API
    to generate a report

    """
    
    def __init__(self,IOC,flag='virustotal'):
        self.flag = flag.lower()
        if flag == 'virustotal':
            self.vt_ioc = IOC
            # The  virus total API and URL are read from the keyconstants.py file.
            self.vt_url = keyconstants.VirusTotal.VT_URL
            self.vt_api_key = keyconstants.VirusTotal.VT_API_KEY
            self.vt_params = {'apikey': self.vt_api_key, 'resource': self.vt_ioc }
        else:
            raise Exception("Currently supporting only VirusTotal for ThreatIntelligence")

        
    def Virus_Total(self):
        response = requests.get(self.vt_url, params=self.vt_params)
        vt_result = response.json()

        if 'scans' in vt_result:
            vt_pd = pd.DataFrame(vt_result['scans'])
            
        else:
            vt_pd = None
        
        if vt_pd.empty:
            raise exception("Please check your IOC, no result found")
        else:
            return vt_pd
        
        
        
class Computer(EventLogDB):

    """
    The class Computer represents a instance of each computer identified from the logs files in EventLogDB()
    Using the object instanceof the Computer you can run commands such as Computer.name(), Computer.operatingsystem()
    Computer.owners(). You can also generate reports by calling the Class Process(), File() and Network()

    """

    
    def __init__(self,eventlogdb,devicename):
        self.devicename = devicename
        self.eventlogdb = eventlogdb
        for computer in self.eventlogdb.computer_pds:
            #if computer['DeviceName'][0] == self.devicename:
            if computer['DeviceName'].head(1).to_string(index=False).strip() == self.devicename:
                #print(computer['DeviceName'][0])
                self.deviceinfo_pd = computer
                #print('I AM HERE')
                break
        
    def __str__(self):
        return f"{self.name()}" 
        
    def name(self):
        # This function returns the name of the machine
        devicename = self.deviceinfo_pd['DeviceName'].head(1).to_string(index=False).strip()
        return devicename
    
    def operatingsystem(self):
        # This function returns the Operating systems of the device
        clientversion = self.deviceinfo_pd['ClientVersion'].head(1).to_string(index=False)
        os_versions = keyconstants.OSConstants.VERSIONS
        return os_versions[clientversion.split('.')[2]]
        
    def owners(self):
        #This function returns the list of users who logged into the machine
        owners = self.deviceinfo_pd['LoggedOnUsers'].unique()
        return owners

    def processactivity(self,processname=None,start_datetime=None,end_datetime=None):
        self.startdatetime = start_datetime
        self.enddatetime = end_datetime
        self.processname=processname
        processobject = Process(self.eventlogdb,self.devicename,self.processname,self.startdatetime,self.enddatetime)
        p = processobject.process_activity()
        return p
     
    
    def suspiciouscommands(self,datetime=None):
        #This function uses the file mitreattack.py to identify if any suspicious commands were executed on the device or not
        p=[]
        self.datetime = datetime
        recon_cmds = mitreattack.Tactics.RECONNAISSANCE_COMMANDS
        ptimeline = self.processactivity(self.datetime)
        for cmd in recon_cmds:
            #print('command',cmd)
            if ptimeline[ptimeline['ProcessCommandLine'].str.lower().str.contains(cmd)].empty:
                pass
            else:
                p.append(ptimeline[ptimeline['ProcessCommandLine'].str.lower().str.contains(cmd)])
                
        suspicious_cmds = pd.concat(p)
        return suspicious_cmds
            
            
    def fileactivity(self,filename=None,start_datetime=None,end_datetime=None):
        self.startdatetime = start_datetime
        self.enddatetime = end_datetime
        self.filename = filename
        fobject = File(self.eventlogdb,self.devicename,self.filename,self.startdatetime,self.enddatetime)
        f = fobject.file_activity()
        return f

    def threatintel(self,IOC,flag='virustotal'):
        self.ioc = IOC
        self.flag = flag.lower()
        if self.flag == 'virustotal':
            TI = ThreatIntelligence(self.ioc,self.flag)
            TI_result = TI.Virus_Total()
            return TI_result
        else:
            print('Currently we only support Virus Total, so please enter the first parameter virustotal')
        
        
    def Reporting(self,output=None,filename=None):
            self.output = output
            self.filename = filename
            #print(self.output)
        
            #if self.output == None:
            #    raise Exception('Please provide a dataframe as a parameter, for example output="computer1",filename="Processactivity.csv"')
            if self.filename == None:
                self.filename = 'Report'+ str(datetime.datetime.now()) + '.csv'
            if type(self.output) == type(pd.DataFrame()):
                self.output.to_csv(self.filename)
            else:
                raise Exception("Please send a Dataframe for Reporting") 
        
            

if __name__=="__main__":

    print("""


               

        ██████╗ ██╗   ██╗██╗██████╗ ██╗      ██████╗  ██████╗  █████╗ ███╗   ██╗ █████╗ ██╗     ██╗   ██╗███████╗██╗███████╗
        ██╔══██╗╚██╗ ██╔╝██║██╔══██╗██║     ██╔═══██╗██╔════╝ ██╔══██╗████╗  ██║██╔══██╗██║     ╚██╗ ██╔╝██╔════╝██║██╔════╝
        ██████╔╝ ╚████╔╝ ██║██████╔╝██║     ██║   ██║██║  ███╗███████║██╔██╗ ██║███████║██║      ╚████╔╝ ███████╗██║███████╗
        ██╔═══╝   ╚██╔╝  ██║██╔══██╗██║     ██║   ██║██║   ██║██╔══██║██║╚██╗██║██╔══██║██║       ╚██╔╝  ╚════██║██║╚════██║
        ██║        ██║   ██║██║  ██║███████╗╚██████╔╝╚██████╔╝██║  ██║██║ ╚████║██║  ██║███████╗   ██║   ███████║██║███████║
        ╚═╝        ╚═╝   ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝╚═╝╚══════╝

        """)


    print("""

            Background:

            The python tool PYIRLogAnalysis (Python Incident Response Log Analysis), it is Operating System and Application Agnostic Log analysis tool. 
            The python tool will parse through different logs files either from Windows, Linux or Third-party applications such as Microsoft Defender endpoint 
            logs. After parsing the logs, it will create python objects. Each object represents the computer device from which the logs files were collected. 
            You can perform actions on these python objects such as generating process activity reports. The current version of the code currently accepts only 
            the Microsoft Defender endpoint logs. 

            Run Instructions:

            1. Run python project.py. Depending on the size and number of the input csv files in ./Log folder, it will take few seconds to parse
               the log files to create panda dataframes.
            2. After the logs files are parsed into dataframes, it will generate the name of the devices from which the logs files were collected.
               For example based on the sample csv files in the Log folder, it should display two computers: Cybercookie1 and Cybercookie2
            3. Type 1 for Cybercookie1 or Type 2 for Cybercookie2. This should create python object representing the computer.
            4. In this step you have the options to choose to look at computer's Name, Owner and Operating System. To go to the next step Type 4.
            5. In this step you have the options to generate csv reports for the computer Process Activity, File Activity, Suspicious Commands and Threat Intelligence.
            6. Type Exit to end the program.


            Sample Commands:
                               
                -  Please enter the name of the computer from the list you would like to investigate: cybercookie1
                -  Please enter the name of the process: powershell.exe
                -  Please enter the name of the file: lsziokgt.dll
                -  Please enter the start time for example "2021-07-04 11:00" , [no quotes]: 2021-07-04 11:00
                -  Please enter the end time for example "2021-07-04 11:30 , [no quotes]": 2021-07-04 11:45
                -  Please enter the IOC -Indicators of Compromise: df9892a9e7e5de380dec73231eee79e7ed1b8b0ee97d3aa1f11ed8cfedf00163



        """)



    eventlogdb = EventLogDB()
    computerlist = eventlogdb.computerlist
    i = 1
    print(f'{len(computerlist)} computers identified in the logs: ')
    for c in computerlist:
        print(f'{i} --> {c}')
        i+=1
    #print(type(computerlist))
    input_value = 'invalid'
    while input_value == 'invalid':
        computername = input('\nPlease enter the name of the computer from the list you would like to investigate: ')
        if computername not in computerlist:
            print('You have entered a invalid computer name, please try again')
        else:
            input_value = 'valid'

    computer_object = Computer(eventlogdb,computername)

    choice = '0'

    while choice != '4':
        choice = input("""\nPlease choose from the following

            1 -> Computer Name
            2 -> Computer Owners
            3 -> Computer Operating System
            4 -> Continue Next for advanced tasks
            5 -> Exit
            

            """)
        if choice == '1':
            print('Computer Name is: ', computer_object.name())

        elif choice == '2':
            print('Computer owners: ', computer_object.owners())

        elif choice == '3':
            print('Computer operating system,: ', computer_object.operatingsystem())            

        elif choice == '4':
            print('Thank you, next....')

        elif choice == '5':
            print('THANK YOU! Exiting Program.........')
            exit()

        elif choice not in ['1','2','3','4']:
            print('Wrong Entry, please try again ')


    choice = '0'
    while choice != '5':
        choice = input("""\nPlease choose from the following

            1 -> Process Activity
            2 -> File Activity
            3 -> Suspicious Commands 
            4 -> ThreatIntelligence
            5 -> Exit

            """)
        if choice == '1':
            sub_choice = input("""\nPlease choose from the following

            a -> All process activity
            b -> Start/End datetime for process activity
            c -> Process activity for a specific process name
            d -> Both b and C
            e -> Skip/Continue

            """)

            if sub_choice.lower() == 'a':
                computer_object_processactivity = computer_object.processactivity()
                file_name = computername + '_AllProcessActivity.csv'
                computer_object.Reporting(output=computer_object_processactivity,filename=file_name)
                print(f'Output file generated: {file_name}')

            elif sub_choice.lower() == 'b':
                startdatetime = str(input('Please enter the start time for example "2021-07-04 11:00" , [no quotes] : '))
                enddatetime = str(input('Please enter the end time for example "2021-07-04 11:30" , [no quotes] : '))
                computer_object_processactivity = computer_object.processactivity(start_datetime=startdatetime,end_datetime=enddatetime)
                file_name = computername + '_' + str(startdatetime.split(' ')[0]) + '_ProcessActivity.csv' 
                computer_object.Reporting(output=computer_object_processactivity,filename=file_name)
                print(f'Output file generated: {file_name}')

            elif sub_choice.lower() == 'c':
                process_name = str(input('Please enter the name of the process: '))
                computer_object_processactivity = computer_object.processactivity(processname=process_name)
                file_name = computername + '_' + process_name + '_ProcessActivity.csv'
                computer_object.Reporting(output=computer_object_processactivity,filename=file_name)
                print(f'Output file generated: {file_name}')

            elif sub_choice.lower() == 'd':
                process_name = str(input('Please enter the name of the process: '))
                startdatetime = str(input('Please enter the start time for example "2021-07-04 11:00" , [no quotes]: '))
                enddatetime = str(input('Please enter the end time for example "2021-07-04 11:30 , [no quotes]": '))
                file_name = computername + '_' + process_name +  '_' + str(startdatetime.split(' ')[0]) + '_ProcessActivity.csv'
                computer_object_processactivity = computer_object.processactivity(processname=process_name,start_datetime=startdatetime,end_datetime=enddatetime)
                computer_object.Reporting(output=computer_object_processactivity,filename=file_name)
                print(f'Output file generated: {file_name}')

            elif sub_choice.lower() == 'e':
                print('Skipping.....')

            
        elif choice == '2':
            sub_choice = input("""\nPlease choose from the following

            a -> All File activity
            b -> Start/End datetime for File activity
            c -> File activity for a specific file name
            d -> Both b and C
            e -> Skip/Continue

            """)

            if sub_choice.lower() == 'a':
                computer_object_fileactivity = computer_object.fileactivity()
                file_name = computername + '_AllFileActivity.csv'
                computer_object.Reporting(output=computer_object_fileactivity,filename=file_name)
                print(f'Output file generated: {file_name}')

            elif sub_choice.lower() == 'b':
                startdatetime = str(input('Please enter the start time for example "2021-07-04 11:00" , [no quotes] : '))
                enddatetime = str(input('Please enter the end time for example "2021-07-04 11:30" , [no quotes] : '))
                computer_object_fileactivity = computer_object.fileactivity(start_datetime=startdatetime,end_datetime=enddatetime)
                file_name = computername + '_' + str(startdatetime.split(' ')[0]) + '_FileActivity.csv' 
                computer_object.Reporting(output=computer_object_fileactivity,filename=file_name)
                print(f'Output file generated: {file_name}')

            elif sub_choice.lower() == 'c':
                file_name = str(input('Please enter the name of the file: '))
                computer_object_fileactivity = computer_object.fileactivity(filename=file_name)
                file_name = computername + '_' + file_name + '_FileActivity.csv'
                computer_object.Reporting(output=computer_object_fileactivity,filename=file_name)
                print(f'Output file generated: {file_name}')

            elif sub_choice.lower() == 'd':
                file_name = str(input('Please enter the name of the file: '))
                startdatetime = str(input('Please enter the start time for example "2021-07-04 11:00" , [no quotes]: '))
                enddatetime = str(input('Please enter the end time for example "2021-07-04 11:30 , [no quotes]": '))
                file_name = computername + '_' + file_name +  '_' + str(startdatetime.split(' ')[0]) + '_FileActivity.csv'
                computer_object_fileactivity = computer_object.fileactivity(filename=file_name,start_datetime=startdatetime,end_datetime=enddatetime)
                computer_object.Reporting(output=computer_object_fileactivity,filename=file_name)
                print(f'Output file generated: {file_name}')

            elif sub_choice.lower() == 'e':
                print('Skipping.....')
        

        elif choice == '3':
            computer_object_suspiciouscommands = computer_object.suspiciouscommands()
            file_name = computername + '_SuspiciousCommandsActivity.csv'
            computer_object.Reporting(output=computer_object_suspiciouscommands,filename=file_name)
            print(f'Output file generated: {file_name}')

        elif choice == '4':
            IOC = input('Please enter the IOC -Indicators of Compromise: ')
            computer_object_threatintel = computer_object.threatintel(IOC)
            file_name = computername + '_ThreatIntelligence.csv'
            computer_object.Reporting(output=computer_object_threatintel,filename=file_name)
            print(f'Output file generated: {file_name}')            

        
        elif choice not in ['1','2','3','4','5']:
            print('Please provide a valid entry')



        elif choice == '5':
            print('THANK YOU! Exiting Program........')
            exit()
