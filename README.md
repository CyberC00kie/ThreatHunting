# ThreatHunting using PYIRLogAnalysis

PYIRLogAnalysis - A Python Tool for Incident Response Log Analysis

    ██████╗ ██╗   ██╗██╗██████╗ ██╗      ██████╗  ██████╗  █████╗ ███╗   ██╗ █████╗ ██╗     ██╗   ██╗███████╗██╗███████╗
    ██╔══██╗╚██╗ ██╔╝██║██╔══██╗██║     ██╔═══██╗██╔════╝ ██╔══██╗████╗  ██║██╔══██╗██║     ╚██╗ ██╔╝██╔════╝██║██╔════╝
    ██████╔╝ ╚████╔╝ ██║██████╔╝██║     ██║   ██║██║  ███╗███████║██╔██╗ ██║███████║██║      ╚████╔╝ ███████╗██║███████╗
    ██╔═══╝   ╚██╔╝  ██║██╔══██╗██║     ██║   ██║██║   ██║██╔══██║██║╚██╗██║██╔══██║██║       ╚██╔╝  ╚════██║██║╚════██║
    ██║        ██║   ██║██║  ██║███████╗╚██████╔╝╚██████╔╝██║  ██║██║ ╚████║██║  ██║███████╗   ██║   ███████║██║███████║
    ╚═╝      

The python tool PYIRLogAnalysis (Python Incident Response Log Analysis), it is Operating System and Application Agnostic Log analysis tool. The python tool will parse through different logs files either from Windows, Linux or Third-party applications such as Microsoft Defender endpoint logs. After parsing the logs, it will create python objects. Each object represents the computer device from which the logs files were collected. You can perform actions on these python objects such as generating process activity reports. The current version of the code currently accepts only the Microsoft Defender endpoint logs.

Run Instructions when running in .py interface:

Run python project.py. Depending on the size and number of the input csv files in ./Log folder, it will take few seconds to parse the log files to create panda dataframes.
After the logs files are parsed into dataframes, it will generate the name of the devices from which the logs files were collected. For example based on the sample csv files in the Log folder, it should display two computers: Cybercookie1 and Cybercookie2
Type 1 for Cybercookie1 or Type 2 for Cybercookie2. This should create python object representing the computer.
In this step you have the options to choose to look at computer's Name, Owner and Operating System. To go to the next step Type 4.
In this step you have the options to generate csv reports for the computer Process Activity, File Activity, Suspicious Commands and Threat Intelligence.
Type Exit to end the program.
Sample Commands when running in .py interface:

Please enter the name of the computer from the list you would like to investigate: cybercookie1
Please enter the name of the process: powershell.exe
Please enter the name of the file: lsziokgt.dll
Please enter the start time for example "2021-07-04 11:00" , [no quotes]: 2021-07-04 11:00
Please enter the end time for example "2021-07-04 11:30 , [no quotes]": 2021-07-04 11:45
Please enter the IOC -Indicators of Compromise: df9892a9e7e5de380dec73231eee79e7ed1b8b0ee97d3aa1f11ed8cfedf00163
