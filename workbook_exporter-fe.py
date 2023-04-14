from flask import Flask, render_template, request, send_from_directory
import os
import sys
import tempfile
import sys
import pandas as pd
import oyaml as yaml
import os
from collections import OrderedDict
from ruamel.yaml import YAML
from flask import flash


class StdoutRedirector(object):
    def __init__(self, text_widget):
        self.text_widget = text_widget

    def write(self, str):
        self.text_widget.insert(END, str)
        self.text_widget.see(END)

    def flush(self):
        pass

global listen_port_var
output_path = None
selected_exporter_names = []

#######################################################   START OF EXPORTER FUNCTIONS   ###################################################################

############################################################ EXPORTER_CALLBACK #####################################################################

def exporter_callback(input_file, output_file, existing_yaml_file=None):
    exporter_generic('exporter_callback', input_file, output_file, existing_yaml_file)

########################################################   exporter_BREEZE   ############################################################

def exporter_breeze(input_file, output_file, existing_yaml_file=None):
    exporter_generic('exporter_breeze', input_file, output_file, existing_yaml_file)


###############################################################  exporter_CMS  #############################################################

def exporter_cms(input_file, output_file, existing_yaml_file=None):
    exporter_generic('exporter_cms', input_file, output_file, existing_yaml_file)

############################################################  EXPORTER_SM  ################################################################################

def exporter_sm(input_file, output_file, existing_yaml_file=None):
    exporter_generic('exporter_sm', input_file, output_file, existing_yaml_file)

####################################################    EXPORTER_LINUX    #############################################################

def exporter_linux(input_file, output_file, existing_yaml_file=None):
    exporter_generic('exporter_linux', input_file, output_file, existing_yaml_file)
######################################################  EXPORTER_BlackBox  #############################################################

def exporter_blackbox(file_path, output_file, existing_yaml_file=None):
    global default_listen_port
    global output_path
    new_entries = []
    sorted_yaml_output = []
    output_dir = tempfile.gettempdir()
    output_path = os.path.join(output_dir, output_file)

    try:
        flash('BlackBox Exporter Called')
        df = read_input_file(file_path)

    except Exception as e:
        flash(f"Error: {e}")
        return

    df_filtered = filter_rows_by_exporter(df, 'exporter_blackbox')
    output_path = os.path.join(output_file)

    # Initialize exporter_blackbox key in the YAML dictionary
    yaml_output = OrderedDict([('exporter_blackbox', OrderedDict())])

    # Check if optional headers are present
    ssh_username_present = 'ssh_username' in df.columns
    ssh_password_present = 'ssh_password' in df.columns

    # Iterate over rows in filtered dataframe
    new_entries = []
    for index, row in df.iterrows():
        exporter_name = 'exporter_blackbox'
        hostname = row['FQDN']
        ip_address = row['IP Address']
        location = row['Location']
        country = row['Country']

        if ip_exists_in_yaml(exporter_name, ip_address, output_path=output_path):
            continue

        if hostname not in yaml_output.get(exporter_name, {}):
             yaml_output[exporter_name][hostname] = {}
    
        if ip_address not in yaml_output[exporter_name][hostname]:
             yaml_output[exporter_name][hostname][ip_address] = {}
        
        yaml_output[exporter_name][hostname][ip_address]['location'] = location
        yaml_output[exporter_name][hostname][ip_address]['country'] = country
    
        if row['icmp']:
            yaml_output[exporter_name][hostname][ip_address]['module'] = 'icmp'
        
        if row['ssh-banner']:
            ssh_ip_address = f"{ip_address}:22"
            if ip_exists_in_yaml(exporter_name, ssh_ip_address, output_path=output_path):
                continue
            yaml_output[exporter_name][hostname][ssh_ip_address] = {
                'module': 'ssh_banner',
                'location': location,
                'country': country
            }

        new_entries.append(row)

    # Write the YAML data to a file, either updating the existing file or creating a new file
    output_path = os.path.join(output_dir, output_file)
    existing_yaml_output = load_existing_yaml(output_path)

    process_exporter('exporter_blackbox', exporter_name, existing_yaml_output, yaml_output, output_path)

########################################################  EXPORTER_SSL  ##################################################################

def exporter_ssl(file_path, output_file, existing_yaml_file=None):
    global default_listen_port
    global output_path
    new_entries = []
    sorted_yaml_output = []
    output_dir = tempfile.gettempdir()
    output_path = os.path.join(output_dir, output_file)

    try:
        flash("Exporter SSL called")
        df = read_input_file(file_path)

    except Exception as e:
        flash(f"Error: {e}")
        return

    # Filter the data based on the condition
    df_filtered = df[df['Exporter_SSL'] == True]

    # Create an empty dictionary to store the YAML output
    yaml_output = OrderedDict([('exporter_ssl', OrderedDict())])

    # Initialize exporter_ssl key in the YAML dictionary
    yaml_output['exporter_ssl'] = {}

    output_path = os.path.join(output_dir, output_file)

    # Initialize new_entries list
    new_entries = []
    # Loop through the filtered data and add to the dictionary
    for _, row in df_filtered.iterrows():
        exporter_name = 'exporter_ssl'
        fqdn = row['FQDN']
        ip_address = row['IP Address']
        location = row['Location']
        country = row['Country']
        exporter_app = row['Exporter_name_app']

        # Set default listen_port to 443 and change it to 8443 if exporter_ssl is specified
        listen_port = 8443 if exporter_app == 'exporter_ssl' else 443

        # Check for duplicate entries
        if ip_exists_in_yaml(exporter_name, ip_address, output_path):
            continue

        if exporter_name not in yaml_output:
            yaml_output[exporter_name] = {}
        if fqdn not in yaml_output[exporter_name]:
            yaml_output[exporter_name][fqdn] = {}
        yaml_output[exporter_name][fqdn] = {
            'ip_address': ip_address,
            'listen_port': listen_port,
            'location': location,
            'country': country,
        }

        new_entries.append(row)

    # Add this line to load existing YAML data
    existing_yaml_output = load_existing_yaml(output_path)
    # Write the YAML data to a file, either appending to an existing file or creating a new file
    process_exporter('exporter_ssl', existing_yaml_output, new_entries, yaml_output, output_path)

##############################################################   exporter_WINDOWS   ########################################################
   
def exporter_windows(file_path, output_file, existing_yaml_file=None):
    global default_listen_port
    global output_path
    new_entries = []
    sorted_yaml_output = []
    output_dir = tempfile.gettempdir()
    output_path = os.path.join(output_dir, output_file)

    try:
        flash("Exporter Windows called")
        df = read_input_file(file_path)

    except Exception as e:
        flash(f"Error: {e}")
        return

    df_filtered = filter_rows_by_exporter(df, 'exporter_windows')
    output_path = os.path.join(output_dir, output_file)

    # Initialize exporter_windows key in the YAML dictionary
    yaml_output = OrderedDict([('exporter_windows', OrderedDict())])

    # Iterate over rows in filtered dataframe
    new_entries = []
    for index, row in df_filtered.iterrows():
        exporter_name = 'exporter_windows'
        fqdn = row['FQDN']
        ip_address = row['IP Address']
        location = row['Location']
        country = row['Country']

        if ip_exists_in_yaml(exporter_name, ip_address, output_path=output_path):
            continue

        if fqdn not in yaml_output[exporter_name]:
            yaml_output[exporter_name][fqdn] = {}

        yaml_output[exporter_name][fqdn]['ip_address'] = ip_address
        yaml_output[exporter_name][fqdn]['listen_port'] = 9182  # Set to default listen port for Windows
        yaml_output[exporter_name][fqdn]['location'] = location
        yaml_output[exporter_name][fqdn]['country'] = country

        new_entries.append(row)

    existing_yaml_output = load_existing_yaml(output_path)

    # Write the YAML data to a file, either updating the existing file or creating a new file
    process_exporter('exporter_windows', existing_yaml_output, new_entries, yaml_output, output_path)
  
 ##########################################################   exporter_VERINT   ###############################################################

def exporter_verint(file_path, output_file, existing_yaml_file=None):
    global default_listen_port
    global output_path
    new_entries = []
    sorted_yaml_output = []
    output_dir = tempfile.gettempdir()
    output_path = os.path.join(output_dir, output_file)

    try:
        flash("Exporter Verint called")
        df = read_input_file(file_path)

    except Exception as e:
        flash(f"Error: {e}")
        return

    df_filtered = filter_rows_by_exporter(df, 'exporter_verint')
    output_path = os.path.join(output_dir, output_file)

    # Initialize exporter_verint key in the YAML dictionary
    yaml_output = OrderedDict([('exporter_verint', OrderedDict())])

    # Iterate over rows in filtered dataframe
    new_entries = []
    for index, row in df_filtered.iterrows():
        exporter_name = 'exporter_verint'
        fqdn = row['FQDN']
        ip_address = row['IP Address']
        location = row['Location']
        country = row['Country']

        if ip_exists_in_yaml(exporter_name, ip_address, output_path=output_path):
            continue

        if fqdn not in yaml_output[exporter_name]:
            yaml_output[exporter_name][fqdn] = {}

        yaml_output[exporter_name][fqdn]['ip_address'] = ip_address
        yaml_output[exporter_name][fqdn]['listen_port'] = 9182
        yaml_output[exporter_name][fqdn]['location'] = location
        yaml_output[exporter_name][fqdn]['country'] = country

        new_entries.append(row)

    existing_yaml_output = load_existing_yaml(output_path)

    # Write the YAML data to a file, either updating the existing file or creating a new file
    process_exporter('exporter_verint', existing_yaml_output, new_entries, yaml_output, output_path)
               
#######################################################   AVAYA SBC   ####################################################################

def exporter_avayasbc(file_path, output_file, output_dir):
    global default_listen_port
    global output_path
    global default_listen_port
    global output_path
    new_entries = []
    sorted_yaml_output = []
    output_dir = tempfile.gettempdir()
    output_path = os.path.join(output_dir, output_file)

    yaml_output = OrderedDict([('exporter_avayasbc', OrderedDict())])

    try:
        print("Exporter SBC called")

        df = read_input_file(file_path)

    except Exception as e:
        print(f"Error: {e}")
        return

    df_filtered = filter_rows_by_exporter(df, 'exporter_avayasbc')
    output_path = os.path.join(output_dir, output_file)

    # Initialize exporter_avayasbc key in the YAML dictionary
    yaml_output = OrderedDict([('exporter_avayasbc', OrderedDict())])

    # Iterate over rows in filtered dataframe
    new_entries = []
    for index, row in df_filtered.iterrows():
        exporter_name = 'exporter_avayasbc'
        hostname = row['FQDN']
        ip_address = row['IP Address']
        location = row['Location']
        country = row['Country']

        if ip_exists_in_yaml(exporter_name, ip_address, output_path=output_path):
            continue

        if hostname not in yaml_output[exporter_name]:
            yaml_output[exporter_name][hostname] = {}

        if ip_address not in yaml_output[exporter_name][hostname]:
            yaml_output[exporter_name][hostname][ip_address] = {}

            yaml_output[exporter_name][hostname][ip_address]['listen_port'] = 3601
            yaml_output[exporter_name][hostname][ip_address]['location'] = location
            yaml_output[exporter_name][hostname][ip_address]['country'] = country
            yaml_output[exporter_name][hostname][ip_address]['username'] = 'ipcs'

            new_entries.append(row)

    # Load existing YAML data
    existing_yaml_output = load_existing_yaml(output_path)  
    # Write the YAML data to a file, either appending to an existing file or creating a new file
    process_exporter('exporter_avayasbc', existing_yaml_output, new_entries, yaml_output, output_path)

###########################################   exporter_GATEWAY   ####################################################################

def exporter_gateway(file_path, output_file, existing_yaml_file=None):
    global default_listen_port
    global output_path
    new_entries = []
    sorted_yaml_output = []
    output_dir = tempfile.gettempdir()
    output_path = os.path.join(output_dir, output_file)

    yaml_output = OrderedDict([('exporter_gateway', OrderedDict())])

    try:
        flash("Exporter Gateway called")

        df = read_input_file(file_path)

    except Exception as e:
        flash(f"Error: {e}")
        return

    df_filtered = filter_rows_by_exporter(df, 'exporter_gateway')
    output_path = os.path.join(output_dir, output_file)

    # Initialize exporter_gateway key in the YAML dictionary
    yaml_output = OrderedDict([('exporter_gateway', OrderedDict())])

    # Iterate over rows in filtered dataframe
    new_entries = []
    for index, row in df_filtered.iterrows():
        exporter_name = 'exporter_gateway'
        hostname = row['Hostnames']
        ip_address = row['IP Address']
        location = row['Location']
        country = row['Country']

        if ip_exists_in_yaml(exporter_name, ip_address, output_path=output_path):
            continue

        if hostname not in yaml_output[exporter_name]:
            yaml_output[exporter_name][hostname] = {}

        if ip_address not in yaml_output[exporter_name][hostname]:
            yaml_output[exporter_name][hostname][ip_address] = {}

        if pd.isna(row['App-Listen-Port']):
            yaml_output[exporter_name][hostname][ip_address]['listen_port'] = int(default_listen_port.get())
        else:
            yaml_output[exporter_name][hostname][ip_address]['listen_port'] = int(row['App-Listen-Port'])

        yaml_output[exporter_name][hostname][ip_address]['location'] = location
        yaml_output[exporter_name][hostname][ip_address]['country'] = country
        yaml_output[exporter_name][hostname][ip_address]['snmp_version'] = 2

        if 'comm_string' in df.columns and not pd.isna(row['comm_string']):
            yaml_output[exporter_name][hostname][ip_address]['community'] = row['comm_string']
        else:
            yaml_output[exporter_name][hostname][ip_address]['community'] = 'ENC'

        new_entries.append(row)

    existing_yaml_output = load_existing_yaml(output_path)  # Add this line to load existing YAML data
    # Write the YAML data to a file, either appending to an existing file or creating a new file
    process_exporter('exporter_gateway', existing_yaml_output, new_entries, yaml_output, output_path)

#######################################################  EXPORTER_TCTI       ############################################################

def exporter_tcti(file_path, output_file, existing_yaml_file=None):
    global default_listen_port
    global output_path
    new_entries = []
    sorted_yaml_output = []
    output_dir = tempfile.gettempdir()
    output_path = os.path.join(output_dir, output_file)

    yaml_output = OrderedDict([('exporter_tcti', OrderedDict())])

    try:
        flash("Exporter TCTI called")

        df = read_input_file(file_path)

    except Exception as e:
        flash(f"Error: {e}")
        return

    df_filtered = filter_rows_by_exporter(df, 'exporter_tcti')
    output_path = os.path.join(output_dir, output_file)
    yaml_output = OrderedDict([('exporter_tcti', OrderedDict())])

    # Iterate over rows in filtered dataframe
    new_entries = []
    for index, row in df_filtered.iterrows():
        hostname = row['FQDN']
        ip_address = row['IP Address']
        location = row['Location']
        country = row['Country']

        if ip_exists_in_yaml('exporter_tcti', ip_address, output_path=output_path):
            continue

        if hostname not in yaml_output['exporter_tcti']:
            yaml_output['exporter_tcti'][hostname] = {}

        jmx_ports_present = 'jmx_ports' in row.index
        if jmx_ports_present and not pd.isna(row['jmx_ports']) and row['jmx_ports']:
            ports = [int(port) for port in row['jmx_ports'].split(',')]
        else:
            ports = [8080, 8081]

        for port in ports:
            if port not in yaml_output['exporter_tcti'][hostname]:
                yaml_output['exporter_tcti'][hostname][int(port)] = {} # Changed this line

            yaml_output['exporter_tcti'][hostname][int(port)]['ip_address'] = ip_address
            yaml_output['exporter_tcti'][hostname][int(port)]['location'] = location
            yaml_output['exporter_tcti'][hostname][int(port)]['country'] = country
            new_entries.append(row)

    # Add this line to load existing YAML data
    existing_yaml_output = load_existing_yaml(output_path)          
    # Write the YAML data to a file, either updating the existing file or creating a new file
    process_exporter('exporter_tcti', existing_yaml_output, new_entries, yaml_output, output_path)

########################################################## EXPORTER_JMX #####################################################################
def exporter_jmx(file_path, output_file, existing_yaml_file=None):
    global default_listen_port
    global output_path
    new_entries = []
    sorted_yaml_output = []
    output_dir = tempfile.gettempdir()
    output_path = os.path.join(output_dir, output_file)

    yaml_output = OrderedDict([('exporter_jmx', OrderedDict())])

    try:
        flash("Exporter JMX called")

        df = read_input_file(file_path)

    except Exception as e:
        flash(f"Error: {e}")
        return

    df_filtered = filter_rows_by_exporter(df, 'exporter_jmx')
    output_path = os.path.join(output_dir, output_file)
    yaml_output = OrderedDict([('exporter_jmx', OrderedDict())])

    # Iterate over rows in filtered dataframe
    new_entries = []
    for index, row in df_filtered.iterrows():
        hostname = row['FQDN']
        ip_address = row['IP Address']
        location = row['Location']
        country = row['Country']

        if ip_exists_in_yaml('exporter_jmx', ip_address, output_path=output_path):
            continue

        if hostname not in yaml_output['exporter_jmx']:
            yaml_output['exporter_jmx'][hostname] = {}

        jmx_ports_present = 'jmx_ports' in row.index
        if jmx_ports_present and not pd.isna(row['jmx_ports']) and row['jmx_ports']:
            ports = [int(port) for port in row['jmx_ports'].split(',')]
        else:
            ports = [8080, 8081]

        for port in ports:
            if port not in yaml_output['exporter_jmx'][hostname]:
                yaml_output['exporter_jmx'][hostname][int(port)] = {} # Changed this line

            yaml_output['exporter_jmx'][hostname][int(port)]['ip_address'] = ip_address
            yaml_output['exporter_jmx'][hostname][int(port)]['location'] = location
            yaml_output['exporter_jmx'][hostname][int(port)]['country'] = country
            new_entries.append(row)

    # Add this line to load existing YAML data
    existing_yaml_output = load_existing_yaml(output_path)          
    # Write the YAML data to a file, either updating the existing file or creating a new file
    process_exporter('exporter_jmx', existing_yaml_output, new_entries, yaml_output, output_path)

######################################################## EXPORTER_VMWARE #######################################################################

def exporter_vmware(file_path, output_file, existing_yaml_file=None):
    global default_listen_port
    global output_path
    new_entries = []
    sorted_yaml_output = []
    output_dir = tempfile.gettempdir()
    output_path = os.path.join(output_dir, output_file)

    yaml_output = OrderedDict([('exporter_vmware', OrderedDict())])

    try:
        flash("Exporter vmware called")

        df = read_input_file(file_path)

    except Exception as e:
        flash(f"Error: {e}")
        return

    df_filtered = filter_rows_by_exporter(df, 'exporter_vmware')
    output_path = os.path.join(output_dir, output_file)

    # Iterate over rows in filtered dataframe
    new_entries = []
    for index, row in df_filtered.iterrows():
        hostname = row['FQDN']
        ip_address = row['IP Address']
        location = row['Location']
        country = row['Country']

        if ip_exists_in_yaml('exporter_vmware', ip_address, output_path=output_path):
            continue

        if hostname not in yaml_output['exporter_vmware']:
            yaml_output['exporter_vmware'][hostname] = {}

        if pd.isna(row['App-Listen-Port']):
            yaml_output['exporter_vmware'][hostname]['listen_port'] = 9272
        else:
            yaml_output['exporter_vmware'][hostname]['listen_port'] = int(row['App-Listen-Port'])

        yaml_output['exporter_vmware'][hostname]['ip_address'] = ip_address
        yaml_output['exporter_vmware'][hostname]['location'] = location
        yaml_output['exporter_vmware'][hostname]['country'] = country
        yaml_output['exporter_vmware'][hostname]['username'] = 'put your username here'
        yaml_output['exporter_vmware'][hostname]['password'] = 'put your password here'

        new_entries.append(row)

    # Add this line to load existing YAML data
    existing_yaml_output = load_existing_yaml(output_path)  

    # Write the YAML data to a file, either updating the existing file or creating a new file
    process_exporter('exporter_vmware', existing_yaml_output, new_entries, yaml_output, output_path)

################################################################ EXPORTER_KAFKA ###############################################################

def exporter_kafka(file_path, output_file, existing_yaml_file=None):
    global default_listen_port
    global output_path
    new_entries = []
    sorted_yaml_output = []
    output_dir = tempfile.gettempdir()
    output_path = os.path.join(output_dir, output_file)

    yaml_output = OrderedDict([('exporter_kafka', OrderedDict())])

    try:
        flash("Exporter Exporter Kafka  called")

        df = read_input_file(file_path)

    except Exception as e:
        flash(f"Error: {e}")
        return

    df_filtered = filter_rows_by_exporter(df, 'exporter_kafka')
    output_path = os.path.join(output_dir, output_file)

    if df_filtered.empty:
        flash("No rows matching exporter_kafka condition found")
        return

    # Initialize exporter_genesyscloud key in the YAML dictionary
    yaml_output = OrderedDict([('exporter_kafka', OrderedDict())])

    # Iterate over rows in filtered dataframe
    new_entries = []
    for index, row in df.iterrows():
        hostname = row['FQDN']
        ip_address = row['IP Address']
        location = row['Location']
        country = row['Country']

        output_path = os.path.join(output_dir, output_file)
        if ip_exists_in_yaml('exporter_kafka', ip_address, output_path=output_path):
            continue

        if hostname not in yaml_output.get('exporter_kafka', {}):
            yaml_output['exporter_kafka'][hostname] = {}

        yaml_output['exporter_kafka'][hostname]['ip_address'] = ip_address
        yaml_output['exporter_kafka'][hostname]['listen_port'] = int(row['App-Listen-Port'])
        yaml_output['exporter_kafka'][hostname]['location'] = location
        yaml_output['exporter_kafka'][hostname]['country'] = country
        yaml_output['exporter_kafka'][hostname]['kafka_port'] = 9092

        new_entries.append(row)

    # Add this line to load existing YAML data
    existing_yaml_output = load_existing_yaml(output_path)  

    # Write the YAML data to a file, either updating the existing file or creating a new file
    process_exporter('exporter_kafka', existing_yaml_output, new_entries, yaml_output, output_path)

############################################################ EXPORTER_DRAC ############################################################################

def exporter_drac(file_path, output_file, existing_yaml_file=None):
    global default_listen_port
    global output_path
    new_entries = []
    sorted_yaml_output = []
    output_dir = tempfile.gettempdir()
    output_path = os.path.join(output_dir, output_file)

    # Initialize exporter_drac key in the YAML dictionary
    yaml_output = OrderedDict([('exporter_drac', OrderedDict())])

    try:
        print("Exporter DRAC called")

        df = read_input_file(file_path)

    except Exception as e:
        print(f"Error: {e}")
        return

    df_filtered = filter_rows_by_exporter(df, 'exporter_drac')
    output_path = os.path.join(output_dir, output_file)

    # Initialize exporter_drac key in the YAML dictionary
    yaml_output = OrderedDict([('exporter_drac', OrderedDict())])

    # Iterate over rows in filtered dataframe
    new_entries = []
    for index, row in df_filtered.iterrows():
        hostname = row['FQDN']
        ip_address = row['IP Address']
        location = row['Location']
        country = row['Country']

        if ip_exists_in_yaml('exporter_drac', ip_address, output_path=output_path):
            continue

        if hostname not in yaml_output['exporter_drac']:
            yaml_output['exporter_drac'][hostname] = {}

        yaml_output['exporter_drac'][hostname]['ip_address'] = ip_address
        yaml_output['exporter_drac'][hostname]['listen_port'] = 623
        yaml_output['exporter_drac'][hostname]['location'] = location
        yaml_output['exporter_drac'][hostname]['country'] = country
        yaml_output['exporter_drac'][hostname]['snmp_version'] = 2
        yaml_output['exporter_drac'][hostname]['community'] = row.get('comm_string', 'ENC')

        new_entries.append(row)

    # Add this line to load existing YAML data
    existing_yaml_output = load_existing_yaml(output_path)  

    # Write the YAML data to a file, either updating the existing file or creating a new file
    process_exporter('exporter_drac', existing_yaml_output, new_entries, yaml_output, output_path)

##################################################### exporter_genesyscloud ##########################################################################

def exporter_genesyscloud(file_path, output_file, existing_yaml_file=None):
    global default_listen_port
    global output_path
    new_entries = []
    sorted_yaml_output = []
    output_dir = tempfile.gettempdir()
    output_path = os.path.join(output_dir, output_file)

    yaml_output = OrderedDict([('exporter_genesyscloud', OrderedDict())])
    
    try:
        print("Exporter Genesys Cloud called")

        df = read_input_file(file_path)

    except Exception as e:
        print(f"Error: {e}")
        return

    df_filtered = filter_rows_by_exporter(df, 'exporter_genesyscloud')
    output_path = os.path.join(output_dir, output_file)

    if df_filtered.empty:
        print("No rows matching exporter_genesyscloud condition found")
        return

    # Initialize exporter_genesyscloud key in the YAML dictionary
    yaml_output = OrderedDict([('exporter_genesyscloud', OrderedDict())])

    # Iterate over rows in filtered dataframe
    new_entries = []
    for index, row in df.iterrows():
        hostname = row['FQDN']
        listen_port = row['App-Listen-Port']
        ip_address = row['IP Address']
        location = row['Location']
        country = row['Country']
        comm_string = row.get('comm_string', 'public')


        if ip_exists_in_yaml('exporter_genesyscloud', ip_address, output_path=output_path):
            continue

        yaml_output['exporter_genesyscloud'][hostname] = OrderedDict([
            ('listen_port', listen_port),
            ('extra_args', (" --client.managed  --billing.enabled --billing.frequency 30m --usage.enabled "
                          "--usage.frequency 12h --client.first-day-of-month 22 --mos.enabled "
                          "--mos.bandceilingcritical 2.59999 --mos.bandceilingbad 3.59999 "
                          "--mos.bandceilingwarning 3.09999 --mos.bandceilinggood 3.99999")),
            ('client_id', 'ENC[PKCS7...]'),
            ('client_secret', 'ENC[PKCS7...]'),
            ('client_basepath', 'https://api.mypurecloud.ie'),
            ('ip_address', ip_address),
            ('location', location),
            ('country', country),
            ('community', comm_string)
        ])

        new_entries.append(row)

    # Add this line to load existing YAML data
    existing_yaml_output = load_existing_yaml(output_path)  
    # Sort the YAML data by hostname before writing it to the output file
    sorted_yaml_output = OrderedDict(sorted(yaml_output['exporter_genesyscloud'].items(), key=lambda x: x[0]))
    # Write the YAML data to a file, either updating the existing file or creating a new file
    process_exporter('exporter_genesyscloud', existing_yaml_output, new_entries, yaml_output, output_path)

################################################################### EXPORTER_ACM #####################################################################

def exporter_acm(file_path, output_file, existing_yaml_file=None):
    global default_listen_port
    global output_path
    new_entries = []
    sorted_yaml_output = []
    output_dir = tempfile.gettempdir()
    output_path = os.path.join(output_dir, output_file)

    yaml_output = OrderedDict([('exporter_acm', OrderedDict())])
    
    try:
        flash("Exporter ACM called")

        df = read_input_file(file_path)

    except Exception as e:
        flash(f"Error: {e}")
        return

    df_filtered = filter_rows_by_exporter(df, 'exporter_acm')
    output_path = os.path.join(output_dir, output_file)

    if df_filtered.empty:
        flash("No rows matching exporter_acm condition found")
        return

    # Initialize exporter_acm key in the YAML dictionary
    yaml_output = OrderedDict([('exporter_acm', OrderedDict())])

    for index, row in df_filtered.iterrows():
        hostname = row['FQDN']
        ip_address = row['IP Address']
        location = row['Location']
        country = row['Country']
        listen_port = row['App-Listen-Port']
        ssh_username = row.get('ssh_username', 'put your username here')
        ssh_password = row.get('ssh_password', 'put your password here')

        if ip_exists_in_yaml('exporter_acm', ip_address, output_path=output_path):
            flash(f"IP {ip_address} already exists in the YAML file.")
            continue

        if hostname not in yaml_output.get('exporter_acm', {}):
            yaml_output['exporter_acm'][hostname] = OrderedDict()

        yaml_output['exporter_acm'][hostname]['ip_address'] = ip_address
        yaml_output['exporter_acm'][hostname]['listen_port'] = int(listen_port) if not pd.isna(listen_port) else int(default_listen_port)
        if 'lsp' in hostname.lower():
            yaml_output['exporter_acm'][hostname]['type'] = 'lsp'
        elif 'ess' in hostname.lower():
            yaml_output['exporter_acm'][hostname]['type'] = 'ess'
        else:
            yaml_output['exporter_acm'][hostname]['type'] = 'acm'
        yaml_output['exporter_acm'][hostname]['location'] = location
        yaml_output['exporter_acm'][hostname]['country'] = country
        yaml_output['exporter_acm'][hostname]['username'] = ssh_username
        yaml_output['exporter_acm'][hostname]['password'] = ssh_password

        new_entries.append(row)

    # Load existing YAML data
    existing_yaml_output = load_existing_yaml(output_path)
    # Sort the YAML data by hostname before writing it to the output file
    sorted_yaml_output = OrderedDict(sorted(yaml_output['exporter_acm'].items(), key=lambda x: x[0]))
    # Write the YAML data to a file, either updating the existing file or creating a new file
    process_exporter('exporter_acm', existing_yaml_output, new_entries, yaml_output, output_path)

################################################################## WEBLM_EXPORTER ##############################################################################

def exporter_weblm(file_path, output_file, existing_yaml_file=None):
    global default_listen_port
    global output_path
    new_entries = []
    sorted_yaml_output = []
    output_dir = tempfile.gettempdir()
    output_path = os.path.join(output_dir, output_file)

    yaml_output = OrderedDict([('exporter_weblm', OrderedDict())])
    
    try:
        flash("Exporter Weblm called")

        df = read_input_file(file_path)

    except Exception as e:
        flash(f"Error: {e}")
        return

    df_filtered = filter_rows_by_exporter(df, 'exporter_weblm')

    if df_filtered.empty:
        print("No rows matching exporter_weblm condition found")
        return

    output_path = os.path.join(output_dir, output_file)

    hostname = df_filtered['FQDN'].iloc[0]

    # Initialize exporter_weblm key in the YAML dictionary
    yaml_output['exporter_weblm'][hostname] = OrderedDict()

    # Iterate over rows in filtered dataframe
    new_entries = []
    for index, row in df_filtered.iterrows():
        ip_address = row['IP Address']
        location = row['Location']
        country = row['Country']
        listen_port = row['App-Listen-Port']
        ssh_username = row.get('ssh_username', 'put your username here')
        ssh_password = row.get('ssh_password', 'put your password here')

        if ip_exists_in_yaml('exporter_weblm', ip_address, output_dir=output_dir, output_file=output_file):
            continue

        yaml_output['exporter_weblm'][hostname]['ip_address'] = ip_address
        yaml_output['exporter_weblm'][hostname]['listen_port'] = int(listen_port) if not pd.isna(listen_port) else int(default_listen_port)
        yaml_output['exporter_weblm'][hostname]['location'] = location
        yaml_output['exporter_weblm'][hostname]['country'] = country
        yaml_output['exporter_weblm'][hostname]['data_path'] = '/opt/Avaya/tomcat/webapps/WebLM/data/'
        yaml_output['exporter_weblm'][hostname]['username'] = ssh_username
        yaml_output['exporter_weblm'][hostname]['password'] = ssh_password

        new_entries.append(row)

    # Load existing YAML data
    existing_yaml_output = load_existing_yaml(output_path)  

    process_exporter('exporter_weblm', existing_yaml_output, new_entries, yaml_output, output_path)

######################################################## exporter_generic ###############################################################################

def exporter_generic(exporter_name, file_path, output_file, existing_yaml_file=None):
    global default_listen_port
    global output_path
    new_entries = []
    sorted_yaml_output = []
    output_dir = tempfile.gettempdir()
    output_path = os.path.join(output_dir, output_file)

    yaml_output = OrderedDict([('exporter_name', OrderedDict())])

    try:
        flash(f"Exporter {exporter_name} called")
        df = read_input_file(file_path)

    except Exception as e:
        flash(f"Error: {e}")
        return

    df_filtered = filter_rows_by_exporter(df, exporter_name)
    output_path = os.path.join(output_dir, output_file)

    yaml_output = {exporter_name: {}}

    for index, row in df_filtered.iterrows():
        process_row_generic(exporter_name, row, yaml_output, default_listen_port)

    new_entries = df_filtered.to_dict('records')
    existing_yaml_output = load_existing_yaml(output_path)

    # Write the YAML data to a file, either updating the existing file or creating a new file
    process_exporter(exporter_name, existing_yaml_output, new_entries, yaml_output, output_path)


###########################################################   process_row_generic   ###################################################################

def process_row_generic(exporter_name, row, yaml_output, default_listen_port, existing_yaml):
    hostname = row['Hostnames']
    ip_address = row['IP Address']
    location = row['Location']
    country = row['Country']

    if ip_exists_in_yaml(exporter_name, ip_address, existing_yaml):
        return

    if hostname not in yaml_output[exporter_name]:
        yaml_output[exporter_name][hostname] = OrderedDict()

    # Use default_listen_port if 'App-Listen-Port' is not available
    listen_port = row.get('App-Listen-Port', default_listen_port)
    if listen_port == default_listen_port:
        default_listen_port += 1

    yaml_output[exporter_name][hostname]['ip_address'] = ip_address
    yaml_output[exporter_name][hostname]['listen_port'] = listen_port
    yaml_output[exporter_name][hostname]['location'] = location
    yaml_output[exporter_name][hostname]['country'] = country

    ssh_username_present = 'ssh_username' in row
    ssh_password_present = 'ssh_password' in row

    # Use the values from the optional headers if present, otherwise use the placeholders
    if ssh_username_present and not pd.isna(row['ssh_username']):
        yaml_output[exporter_name][hostname]['username'] = row['ssh_username']
    else:
        yaml_output[exporter_name][hostname]['username'] = 'root'

    if ssh_password_present and not pd.isna(row['ssh_password']):
        yaml_output[exporter_name][hostname]['password'] = row['ssh_password']
    else:
        yaml_output[exporter_name][hostname]['password'] = 'ENC'


#####################################################   filter_rows_by_exporter   ################################################################

def filter_rows_by_exporter(df, exporter_name):
    os_exporters = ['exporter_linux', 'exporter_windows', 'exporter_verint', 'exporter_vmware']
    
    if exporter_name in os_exporters:
        column_name = 'Exporter_name_os'
    else:
        column_name = 'Exporter_name_app'
    
    return df[df[column_name] == exporter_name]

#####################################################     read input file    ##########################################################################

def read_input_file(file_path):
    # Check if file is CSV or Excel
    file_extension = os.path.splitext(file_path)[1]
    if file_extension == '.csv':
        # Read CSV file into pandas
        df = pd.read_csv(file_path, skiprows=7)
    elif file_extension in ['.xlsx', '.xls']:
        # Read Excel file into pandas
        df = pd.read_excel(file_path, sheet_name='Sheet2', skiprows=range(0, 6))
    else:
        raise ValueError("Invalid file type. Only CSV and Excel files are supported.")
    return df

################################################### write to Yaml file and print.F   #################################################################

def process_exporter(exporter_name, existing_yaml_output, new_entries, yaml_output, output_path):
    # Write the YAML data to a file, either updating the existing file or creating a new file
    if new_entries:
        # Sort the YAML data by hostname before writing it to the output file
        sorted_yaml_output = OrderedDict(sorted(yaml_output.items(), key=lambda x: x[0]))
        # write to the output file
        write_yaml(existing_yaml_output, sorted_yaml_output, output_path)
        print(f"{exporter_name} completed")
        print(f"Total number of hosts processed: {len(new_entries)}")
    else:
        print(f"{exporter_name} completed - nothing to do")

########################################################## load existing yaml  ###########################################################################

def load_existing_yaml(existing_yaml_file):
    if existing_yaml_file:
        existing_yaml = yaml.safe_load(existing_yaml_file)
        if existing_yaml is None:
            existing_yaml = {}
        return existing_yaml
    else:
        return {}

################################################    Check if IP in Yaml exists in filetered csv  #########################################################

def ip_exists_in_yaml(exporter_name, ip_address, existing_yaml):
    """
    Check if the given IP address already exists in the existing_yaml data for the given exporter
    """
    if existing_yaml is None or exporter_name not in existing_yaml:
        return False

    for hostname, ip_data in existing_yaml[exporter_name].items():
        if 'ip_address' in ip_data and ip_data['ip_address'] == ip_address:
            return True

    return False


######################################################      Write Yaml    ################################################################################

def write_yaml(existing_yaml_output, yaml_output, output_path):
    # Update the existing YAML data with the new entries
    for key, value in yaml_output.items():
        if key not in existing_yaml_output:
            existing_yaml_output[key] = {}
        existing_yaml_output[key].update(value)

    # Write the updated YAML data back to the file
    with open(output_path, 'w', encoding='utf8') as f:
        yaml.dump(existing_yaml_output, f, allow_unicode=True)

########

def dict_representer(dumper, data):
    return dumper.represent_dict(data.items())

def dict_constructor(loader, node):
    return OrderedDict(loader.construct_pairs(node))

yaml.add_representer(OrderedDict, dict_representer)
yaml.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, dict_constructor)

#######################################################   MAIN SECTION  FLASK    ##################################################################################


exporter_functions = {
    'exporter_linux': exporter_linux,
    'exporter_blackbox': exporter_blackbox,
    'exporter_ssl': exporter_ssl,
    'exporter_cms': exporter_cms,
    'exporter_windows': exporter_windows,
    'exporter_avayasbc': exporter_avayasbc,
    'exporter_verint': exporter_verint,
    'exporter_gateway': exporter_gateway,
    'exporter_breeze': exporter_breeze,
    'exporter_sm': exporter_sm,
    'exporter_acm': exporter_acm,
    'exporter_jmx': exporter_jmx,
    'exporter_weblm': exporter_weblm,
    'exporter_vmware': exporter_vmware,
    'exporter_kafka': exporter_kafka,
    'exporter_callback': exporter_callback,
    'exporter_drac': exporter_drac,
    'exporter_genesyscloud': exporter_genesyscloud,
    'exporter_tcti': exporter_tcti
}



app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Handle the form submission
        uploaded_file = request.files.get('file')
        selected_exporters = request.form.getlist('exporters')
        default_listen_port = request.form.get('default_listen_port')
        existing_yaml_file = request.files.get('existing_yaml')

        # Save the uploaded file to a temporary location
        if uploaded_file:
            uploaded_file_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(uploaded_file.filename))
            uploaded_file.save(uploaded_file_path)

        # Process each selected exporter
        for exporter in selected_exporters:
            if exporter in exporter_functions:
                exporter_functions[exporter](uploaded_file_path, 'converted.yaml', existing_yaml_file)
            else:
                print(f"Error: {exporter} not found in exporter_functions")

        # Save the output file to the temporary directory
        output_file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'converted.yaml')

        return render_template('index.html', result_file='converted.yaml')

    return render_template('index.html')

@app.route('/download/<file_name>')
def download(file_name):
    return send_from_directory(app.config['UPLOAD_FOLDER'], file_name, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)

############################################################  EXPORTER_SM  ################################################################################

def exporter_sm(input_file, output_file, existing_yaml_file=None):
    exporter_generic('exporter_sm', input_file, output_file, existing_yaml_file)

####################################################    EXPORTER_LINUX    #############################################################

def exporter_linux(input_file, output_file, existing_yaml_file=None):
    exporter_generic('exporter_linux', input_file, output_file, existing_yaml_file)
######################################################  EXPORTER_BlackBox  #############################################################

def exporter_blackbox(file_path, output_file, existing_yaml_file=None):
    global default_listen_port
    global output_path
    new_entries = []
    sorted_yaml_output = []
    output_dir = tempfile.gettempdir()
    output_path = os.path.join(output_dir, output_file)

    try:
        flash('BlackBox Exporter Called')
        df = read_input_file(file_path)

    except Exception as e:
        flash(f"Error: {e}")
        return

    df_filtered = filter_rows_by_exporter(df, 'exporter_blackbox')
    output_path = os.path.join(output_file)

    # Initialize exporter_blackbox key in the YAML dictionary
    yaml_output = OrderedDict([('exporter_blackbox', OrderedDict())])

    # Check if optional headers are present
    ssh_username_present = 'ssh_username' in df.columns
    ssh_password_present = 'ssh_password' in df.columns

    # Iterate over rows in filtered dataframe
    new_entries = []
    for index, row in df.iterrows():
        exporter_name = 'exporter_blackbox'
        hostname = row['FQDN']
        ip_address = row['IP Address']
        location = row['Location']
        country = row['Country']

        if ip_exists_in_yaml(exporter_name, ip_address, output_path=output_path):
            continue

        if hostname not in yaml_output.get(exporter_name, {}):
             yaml_output[exporter_name][hostname] = {}
    
        if ip_address not in yaml_output[exporter_name][hostname]:
             yaml_output[exporter_name][hostname][ip_address] = {}
        
        yaml_output[exporter_name][hostname][ip_address]['location'] = location
        yaml_output[exporter_name][hostname][ip_address]['country'] = country
    
        if row['icmp']:
            yaml_output[exporter_name][hostname][ip_address]['module'] = 'icmp'
        
        if row['ssh-banner']:
            ssh_ip_address = f"{ip_address}:22"
            if ip_exists_in_yaml(exporter_name, ssh_ip_address, output_path=output_path):
                continue
            yaml_output[exporter_name][hostname][ssh_ip_address] = {
                'module': 'ssh_banner',
                'location': location,
                'country': country
            }

        new_entries.append(row)

    # Write the YAML data to a file, either updating the existing file or creating a new file
    output_path = os.path.join(output_dir, output_file)
    existing_yaml_output = load_existing_yaml(output_path)

    process_exporter('exporter_blackbox', exporter_name, existing_yaml_output, yaml_output, output_path)

########################################################  EXPORTER_SSL  ##################################################################

def exporter_ssl(file_path, output_file, existing_yaml_file=None):
    global default_listen_port
    global output_path
    new_entries = []
    sorted_yaml_output = []
    output_dir = tempfile.gettempdir()
    output_path = os.path.join(output_dir, output_file)

    try:
        flash("Exporter SSL called")
        df = read_input_file(file_path)

    except Exception as e:
        flash(f"Error: {e}")
        return

    # Filter the data based on the condition
    df_filtered = df[df['Exporter_SSL'] == True]

    # Create an empty dictionary to store the YAML output
    yaml_output = OrderedDict([('exporter_ssl', OrderedDict())])

    # Initialize exporter_ssl key in the YAML dictionary
    yaml_output['exporter_ssl'] = {}

    output_path = os.path.join(output_dir, output_file)

    # Initialize new_entries list
    new_entries = []
    # Loop through the filtered data and add to the dictionary
    for _, row in df_filtered.iterrows():
        exporter_name = 'exporter_ssl'
        fqdn = row['FQDN']
        ip_address = row['IP Address']
        location = row['Location']
        country = row['Country']
        exporter_app = row['Exporter_name_app']

        # Set default listen_port to 443 and change it to 8443 if exporter_ssl is specified
        listen_port = 8443 if exporter_app == 'exporter_ssl' else 443

        # Check for duplicate entries
        if ip_exists_in_yaml(exporter_name, ip_address, output_path):
            continue

        if exporter_name not in yaml_output:
            yaml_output[exporter_name] = {}
        if fqdn not in yaml_output[exporter_name]:
            yaml_output[exporter_name][fqdn] = {}
        yaml_output[exporter_name][fqdn] = {
            'ip_address': ip_address,
            'listen_port': listen_port,
            'location': location,
            'country': country,
        }

        new_entries.append(row)

    # Add this line to load existing YAML data
    existing_yaml_output = load_existing_yaml(output_path)
    # Write the YAML data to a file, either appending to an existing file or creating a new file
    process_exporter('exporter_ssl', existing_yaml_output, new_entries, yaml_output, output_path)

##############################################################   exporter_WINDOWS   ########################################################
   
def exporter_windows(file_path, output_file, existing_yaml_file=None):
    global default_listen_port
    global output_path
    new_entries = []
    sorted_yaml_output = []
    output_dir = tempfile.gettempdir()
    output_path = os.path.join(output_dir, output_file)

    try:
        flash("Exporter Windows called")
        df = read_input_file(file_path)

    except Exception as e:
        flash(f"Error: {e}")
        return

    df_filtered = filter_rows_by_exporter(df, 'exporter_windows')
    output_path = os.path.join(output_dir, output_file)

    # Initialize exporter_windows key in the YAML dictionary
    yaml_output = OrderedDict([('exporter_windows', OrderedDict())])

    # Iterate over rows in filtered dataframe
    new_entries = []
    for index, row in df_filtered.iterrows():
        exporter_name = 'exporter_windows'
        fqdn = row['FQDN']
        ip_address = row['IP Address']
        location = row['Location']
        country = row['Country']

        if ip_exists_in_yaml(exporter_name, ip_address, output_path=output_path):
            continue

        if fqdn not in yaml_output[exporter_name]:
            yaml_output[exporter_name][fqdn] = {}

        yaml_output[exporter_name][fqdn]['ip_address'] = ip_address
        yaml_output[exporter_name][fqdn]['listen_port'] = 9182  # Set to default listen port for Windows
        yaml_output[exporter_name][fqdn]['location'] = location
        yaml_output[exporter_name][fqdn]['country'] = country

        new_entries.append(row)

    existing_yaml_output = load_existing_yaml(output_path)

    # Write the YAML data to a file, either updating the existing file or creating a new file
    process_exporter('exporter_windows', existing_yaml_output, new_entries, yaml_output, output_path)
  
 ##########################################################   exporter_VERINT   ###############################################################

def exporter_verint(file_path, output_file, existing_yaml_file=None):
    global default_listen_port
    global output_path
    new_entries = []
    sorted_yaml_output = []
    output_dir = tempfile.gettempdir()
    output_path = os.path.join(output_dir, output_file)

    try:
        flash("Exporter Verint called")
        df = read_input_file(file_path)

    except Exception as e:
        flash(f"Error: {e}")
        return

    df_filtered = filter_rows_by_exporter(df, 'exporter_verint')
    output_path = os.path.join(output_dir, output_file)

    # Initialize exporter_verint key in the YAML dictionary
    yaml_output = OrderedDict([('exporter_verint', OrderedDict())])

    # Iterate over rows in filtered dataframe
    new_entries = []
    for index, row in df_filtered.iterrows():
        exporter_name = 'exporter_verint'
        fqdn = row['FQDN']
        ip_address = row['IP Address']
        location = row['Location']
        country = row['Country']

        if ip_exists_in_yaml(exporter_name, ip_address, output_path=output_path):
            continue

        if fqdn not in yaml_output[exporter_name]:
            yaml_output[exporter_name][fqdn] = {}

        yaml_output[exporter_name][fqdn]['ip_address'] = ip_address
        yaml_output[exporter_name][fqdn]['listen_port'] = 9182
        yaml_output[exporter_name][fqdn]['location'] = location
        yaml_output[exporter_name][fqdn]['country'] = country

        new_entries.append(row)

    existing_yaml_output = load_existing_yaml(output_path)

    # Write the YAML data to a file, either updating the existing file or creating a new file
    process_exporter('exporter_verint', existing_yaml_output, new_entries, yaml_output, output_path)
               
#######################################################   AVAYA SBC   ####################################################################

def exporter_avayasbc(file_path, output_file, output_dir):
    global default_listen_port
    global output_path
    yaml_output = {'exporter_avayasbc': {}}
    try:
        print("Exporter SBC called")

        df = read_input_file(file_path)

    except Exception as e:
        print(f"Error: {e}")
        return

    df_filtered = filter_rows_by_exporter(df, 'exporter_avayasbc')
    output_path = os.path.join(output_dir, output_file)

    # Initialize exporter_avayasbc key in the YAML dictionary
    yaml_output = OrderedDict([('exporter_avayasbc', OrderedDict())])

    # Iterate over rows in filtered dataframe
    new_entries = []
    for index, row in df_filtered.iterrows():
        exporter_name = 'exporter_avayasbc'
        hostname = row['FQDN']
        ip_address = row['IP Address']
        location = row['Location']
        country = row['Country']

        if ip_exists_in_yaml(exporter_name, ip_address, output_path=output_path):
            continue

        if hostname not in yaml_output[exporter_name]:
            yaml_output[exporter_name][hostname] = {}

        if ip_address not in yaml_output[exporter_name][hostname]:
            yaml_output[exporter_name][hostname][ip_address] = {}

            yaml_output[exporter_name][hostname][ip_address]['listen_port'] = 3601
            yaml_output[exporter_name][hostname][ip_address]['location'] = location
            yaml_output[exporter_name][hostname][ip_address]['country'] = country
            yaml_output[exporter_name][hostname][ip_address]['username'] = 'ipcs'

            new_entries.append(row)

    # Load existing YAML data
    existing_yaml_output = load_existing_yaml(output_path)  
    # Write the YAML data to a file, either appending to an existing file or creating a new file
    process_exporter('exporter_avayasbc', existing_yaml_output, new_entries, yaml_output, output_path)

###########################################   exporter_GATEWAY   ####################################################################

def exporter_gateway(file_path, output_file, output_dir):
    global default_listen_port
    global output_path

    try:
        print("Exporter Gateway called")

        df = read_input_file(file_path)

    except Exception as e:
        print(f"Error: {e}")
        return

    df_filtered = filter_rows_by_exporter(df, 'exporter_gateway')
    output_path = os.path.join(output_dir, output_file)

    # Initialize exporter_gateway key in the YAML dictionary
    yaml_output = OrderedDict([('exporter_gateway', OrderedDict())])

    # Iterate over rows in filtered dataframe
    new_entries = []
    for index, row in df_filtered.iterrows():
        exporter_name = 'exporter_gateway'
        hostname = row['Hostnames']
        ip_address = row['IP Address']
        location = row['Location']
        country = row['Country']

        if ip_exists_in_yaml(exporter_name, ip_address, output_path=output_path):
            continue

        if hostname not in yaml_output[exporter_name]:
            yaml_output[exporter_name][hostname] = {}

        if ip_address not in yaml_output[exporter_name][hostname]:
            yaml_output[exporter_name][hostname][ip_address] = {}

        if pd.isna(row['App-Listen-Port']):
            yaml_output[exporter_name][hostname][ip_address]['listen_port'] = int(default_listen_port.get())
        else:
            yaml_output[exporter_name][hostname][ip_address]['listen_port'] = int(row['App-Listen-Port'])

        yaml_output[exporter_name][hostname][ip_address]['location'] = location
        yaml_output[exporter_name][hostname][ip_address]['country'] = country
        yaml_output[exporter_name][hostname][ip_address]['snmp_version'] = 2

        if 'comm_string' in df.columns and not pd.isna(row['comm_string']):
            yaml_output[exporter_name][hostname][ip_address]['community'] = row['comm_string']
        else:
            yaml_output[exporter_name][hostname][ip_address]['community'] = 'ENC'

        new_entries.append(row)

    existing_yaml_output = load_existing_yaml(output_path)  # Add this line to load existing YAML data
    # Write the YAML data to a file, either appending to an existing file or creating a new file
    process_exporter('exporter_gateway', existing_yaml_output, new_entries, yaml_output, output_path)

#######################################################  EXPORTER_TCTI       ############################################################

def exporter_tcti(file_path, output_file, output_dir):
    global default_listen_port
    global output_path

    try:
        print("Exporter TCTI called")

        df = read_input_file(file_path)

    except Exception as e:
        print(f"Error: {e}")
        return

    df_filtered = filter_rows_by_exporter(df, 'exporter_tcti')
    output_path = os.path.join(output_dir, output_file)
    yaml_output = OrderedDict([('exporter_tcti', OrderedDict())])

    # Iterate over rows in filtered dataframe
    new_entries = []
    for index, row in df_filtered.iterrows():
        hostname = row['FQDN']
        ip_address = row['IP Address']
        location = row['Location']
        country = row['Country']

        if ip_exists_in_yaml('exporter_tcti', ip_address, output_path=output_path):
            continue

        if hostname not in yaml_output['exporter_tcti']:
            yaml_output['exporter_tcti'][hostname] = {}

        jmx_ports_present = 'jmx_ports' in row.index
        if jmx_ports_present and not pd.isna(row['jmx_ports']) and row['jmx_ports']:
            ports = [int(port) for port in row['jmx_ports'].split(',')]
        else:
            ports = [8080, 8081]

        for port in ports:
            if port not in yaml_output['exporter_tcti'][hostname]:
                yaml_output['exporter_tcti'][hostname][int(port)] = {} # Changed this line

            yaml_output['exporter_tcti'][hostname][int(port)]['ip_address'] = ip_address
            yaml_output['exporter_tcti'][hostname][int(port)]['location'] = location
            yaml_output['exporter_tcti'][hostname][int(port)]['country'] = country
            new_entries.append(row)

    # Add this line to load existing YAML data
    existing_yaml_output = load_existing_yaml(output_path)          
    # Write the YAML data to a file, either updating the existing file or creating a new file
    process_exporter('exporter_tcti', existing_yaml_output, new_entries, yaml_output, output_path)

########################################################## EXPORTER_JMX #####################################################################
def exporter_jmx(file_path, output_file, output_dir):
    global default_listen_port
    global output_path

    try:
        print("Exporter JMX called")

        df = read_input_file(file_path)

    except Exception as e:
        print(f"Error: {e}")
        return

    df_filtered = filter_rows_by_exporter(df, 'exporter_jmx')
    output_path = os.path.join(output_dir, output_file)
    yaml_output = OrderedDict([('exporter_jmx', OrderedDict())])

    # Iterate over rows in filtered dataframe
    new_entries = []
    for index, row in df_filtered.iterrows():
        hostname = row['FQDN']
        ip_address = row['IP Address']
        location = row['Location']
        country = row['Country']

        if ip_exists_in_yaml('exporter_jmx', ip_address, output_path=output_path):
            continue

        if hostname not in yaml_output['exporter_jmx']:
            yaml_output['exporter_jmx'][hostname] = {}

        jmx_ports_present = 'jmx_ports' in row.index
        if jmx_ports_present and not pd.isna(row['jmx_ports']) and row['jmx_ports']:
            ports = [int(port) for port in row['jmx_ports'].split(',')]
        else:
            ports = [8080, 8081]

        for port in ports:
            if port not in yaml_output['exporter_jmx'][hostname]:
                yaml_output['exporter_jmx'][hostname][int(port)] = {} # Changed this line

            yaml_output['exporter_jmx'][hostname][int(port)]['ip_address'] = ip_address
            yaml_output['exporter_jmx'][hostname][int(port)]['location'] = location
            yaml_output['exporter_jmx'][hostname][int(port)]['country'] = country
            new_entries.append(row)

    # Add this line to load existing YAML data
    existing_yaml_output = load_existing_yaml(output_path)          
    # Write the YAML data to a file, either updating the existing file or creating a new file
    process_exporter('exporter_jmx', existing_yaml_output, new_entries, yaml_output, output_path)

######################################################## EXPORTER_VMWARE #######################################################################

def exporter_vmware(file_path, output_file, output_dir):
    global default_listen_port
    global output_path
    yaml_output = OrderedDict([('exporter_vmware', OrderedDict())])
    try:
        print("Exporter vmware called")

        df = read_input_file(file_path)

    except Exception as e:
        print(f"Error: {e}")
        return

    df_filtered = filter_rows_by_exporter(df, 'exporter_vmware')
    output_path = os.path.join(output_dir, output_file)

    # Iterate over rows in filtered dataframe
    new_entries = []
    for index, row in df_filtered.iterrows():
        hostname = row['FQDN']
        ip_address = row['IP Address']
        location = row['Location']
        country = row['Country']

        if ip_exists_in_yaml('exporter_vmware', ip_address, output_path=output_path):
            continue

        if hostname not in yaml_output['exporter_vmware']:
            yaml_output['exporter_vmware'][hostname] = {}

        if pd.isna(row['App-Listen-Port']):
            yaml_output['exporter_vmware'][hostname]['listen_port'] = 9272
        else:
            yaml_output['exporter_vmware'][hostname]['listen_port'] = int(row['App-Listen-Port'])

        yaml_output['exporter_vmware'][hostname]['ip_address'] = ip_address
        yaml_output['exporter_vmware'][hostname]['location'] = location
        yaml_output['exporter_vmware'][hostname]['country'] = country
        yaml_output['exporter_vmware'][hostname]['username'] = 'put your username here'
        yaml_output['exporter_vmware'][hostname]['password'] = 'put your password here'

        new_entries.append(row)

    # Add this line to load existing YAML data
    existing_yaml_output = load_existing_yaml(output_path)  

    # Write the YAML data to a file, either updating the existing file or creating a new file
    process_exporter('exporter_vmware', existing_yaml_output, new_entries, yaml_output, output_path)

################################################################ EXPORTER_KAFKA ###############################################################

def exporter_kafka(file_path, output_file, output_dir):
    global default_listen_port
    global output_path
    new_entries = []

    try:
        print("Exporter Exporter Kafka  called")

        df = read_input_file(file_path)

    except Exception as e:
        print(f"Error: {e}")
        return

    df_filtered = filter_rows_by_exporter(df, 'exporter_kafka')
    output_path = os.path.join(output_dir, output_file)

    if df_filtered.empty:
        print("No rows matching exporter_kafka condition found")
        return

    # Initialize exporter_genesyscloud key in the YAML dictionary
    yaml_output = OrderedDict([('exporter_kafka', OrderedDict())])

    # Iterate over rows in filtered dataframe
    new_entries = []
    for index, row in df.iterrows():
        hostname = row['FQDN']
        ip_address = row['IP Address']
        location = row['Location']
        country = row['Country']

        output_path = os.path.join(output_dir, output_file)
        if ip_exists_in_yaml('exporter_kafka', ip_address, output_path=output_path):
            continue

        if hostname not in yaml_output.get('exporter_kafka', {}):
            yaml_output['exporter_kafka'][hostname] = {}

        yaml_output['exporter_kafka'][hostname]['ip_address'] = ip_address
        yaml_output['exporter_kafka'][hostname]['listen_port'] = int(row['App-Listen-Port'])
        yaml_output['exporter_kafka'][hostname]['location'] = location
        yaml_output['exporter_kafka'][hostname]['country'] = country
        yaml_output['exporter_kafka'][hostname]['kafka_port'] = 9092

        new_entries.append(row)

    # Add this line to load existing YAML data
    existing_yaml_output = load_existing_yaml(output_path)  

    # Write the YAML data to a file, either updating the existing file or creating a new file
    process_exporter('exporter_kafka', existing_yaml_output, new_entries, yaml_output, output_path)

############################################################ EXPORTER_DRAC ############################################################################

def exporter_drac(file_path, output_file, output_dir):
    global default_listen_port
    global output_path

    # Initialize exporter_kafka key in the YAML dictionary
    yaml_output = {'exporter_drac': {}}

    try:
        print("Exporter DRAC called")

        df = read_input_file(file_path)

    except Exception as e:
        print(f"Error: {e}")
        return

    df_filtered = filter_rows_by_exporter(df, 'exporter_drac')
    output_path = os.path.join(output_dir, output_file)

    # Initialize exporter_drac key in the YAML dictionary
    yaml_output = OrderedDict([('exporter_drac', OrderedDict())])

    # Iterate over rows in filtered dataframe
    new_entries = []
    for index, row in df_filtered.iterrows():
        hostname = row['FQDN']
        ip_address = row['IP Address']
        location = row['Location']
        country = row['Country']

        if ip_exists_in_yaml('exporter_drac', ip_address, output_path=output_path):
            continue

        if hostname not in yaml_output['exporter_drac']:
            yaml_output['exporter_drac'][hostname] = {}

        yaml_output['exporter_drac'][hostname]['ip_address'] = ip_address
        yaml_output['exporter_drac'][hostname]['listen_port'] = 623
        yaml_output['exporter_drac'][hostname]['location'] = location
        yaml_output['exporter_drac'][hostname]['country'] = country
        yaml_output['exporter_drac'][hostname]['snmp_version'] = 2
        yaml_output['exporter_drac'][hostname]['community'] = row.get('comm_string', 'ENC')

        new_entries.append(row)

    # Add this line to load existing YAML data
    existing_yaml_output = load_existing_yaml(output_path)  

    # Write the YAML data to a file, either updating the existing file or creating a new file
    process_exporter('exporter_drac', existing_yaml_output, new_entries, yaml_output, output_path)

##################################################### exporter_genesyscloud ##########################################################################

def exporter_genesyscloud(file_path, output_file, output_dir):
def exporter_genesyscloud(file_path, output_file, existing_yaml_file=None):
    global default_listen_port
    global output_path
    new_entries = []
    sorted_yaml_output = []
    output_dir = tempfile.gettempdir()
    output_path = os.path.join(output_dir, output_file)
    
    try:
        print("Exporter Genesys Cloud called")

        df = read_input_file(file_path)

    except Exception as e:
        print(f"Error: {e}")
        return

    df_filtered = filter_rows_by_exporter(df, 'exporter_genesyscloud')
    output_path = os.path.join(output_dir, output_file)

    if df_filtered.empty:
        print("No rows matching exporter_genesyscloud condition found")
        return

    # Initialize exporter_genesyscloud key in the YAML dictionary
    yaml_output = OrderedDict([('exporter_genesyscloud', OrderedDict())])

    # Iterate over rows in filtered dataframe
    new_entries = []
    for index, row in df.iterrows():
        hostname = row['FQDN']
        listen_port = row['App-Listen-Port']
        ip_address = row['IP Address']
        location = row['Location']
        country = row['Country']
        comm_string = row.get('comm_string', 'public')


        if ip_exists_in_yaml('exporter_genesyscloud', ip_address, output_path=output_path):
            continue

        yaml_output['exporter_genesyscloud'][hostname] = OrderedDict([
            ('listen_port', listen_port),
            ('extra_args', (" --client.managed  --billing.enabled --billing.frequency 30m --usage.enabled "
                          "--usage.frequency 12h --client.first-day-of-month 22 --mos.enabled "
                          "--mos.bandceilingcritical 2.59999 --mos.bandceilingbad 3.59999 "
                          "--mos.bandceilingwarning 3.09999 --mos.bandceilinggood 3.99999")),
            ('client_id', 'ENC[PKCS7...]'),
            ('client_secret', 'ENC[PKCS7...]'),
            ('client_basepath', 'https://api.mypurecloud.ie'),
            ('ip_address', ip_address),
            ('location', location),
            ('country', country),
            ('community', comm_string)
        ])

        new_entries.append(row)

    # Add this line to load existing YAML data
    existing_yaml_output = load_existing_yaml(output_path)  
    # Sort the YAML data by hostname before writing it to the output file
    sorted_yaml_output = OrderedDict(sorted(yaml_output['exporter_genesyscloud'].items(), key=lambda x: x[0]))
    # Write the YAML data to a file, either updating the existing file or creating a new file
    process_exporter('exporter_genesyscloud', existing_yaml_output, new_entries, yaml_output, output_path)

################################################################### EXPORTER_ACM #####################################################################

def exporter_acm(file_path, output_file, existing_yaml_file=None):
    global default_listen_port
    global output_path
    new_entries = []
    sorted_yaml_output = []
    output_dir = tempfile.gettempdir()
    output_path = os.path.join(output_dir, output_file)
    
    try:
        flash("Exporter ACM called")

        df = read_input_file(file_path)

    except Exception as e:
        flash(f"Error: {e}")
        return

    df_filtered = filter_rows_by_exporter(df, 'exporter_acm')
    output_path = os.path.join(output_dir, output_file)

    if df_filtered.empty:
        flash("No rows matching exporter_acm condition found")
        return

    # Initialize exporter_acm key in the YAML dictionary
    yaml_output = OrderedDict([('exporter_acm', OrderedDict())])

    for index, row in df_filtered.iterrows():
        hostname = row['FQDN']
        ip_address = row['IP Address']
        location = row['Location']
        country = row['Country']
        listen_port = row['App-Listen-Port']
        ssh_username = row.get('ssh_username', 'put your username here')
        ssh_password = row.get('ssh_password', 'put your password here')

        if ip_exists_in_yaml('exporter_acm', ip_address, output_path=output_path):
            flash(f"IP {ip_address} already exists in the YAML file.")
            continue

        if hostname not in yaml_output.get('exporter_acm', {}):
            yaml_output['exporter_acm'][hostname] = OrderedDict()

        yaml_output['exporter_acm'][hostname]['ip_address'] = ip_address
        yaml_output['exporter_acm'][hostname]['listen_port'] = int(listen_port) if not pd.isna(listen_port) else int(default_listen_port)
        if 'lsp' in hostname.lower():
            yaml_output['exporter_acm'][hostname]['type'] = 'lsp'
        elif 'ess' in hostname.lower():
            yaml_output['exporter_acm'][hostname]['type'] = 'ess'
        else:
            yaml_output['exporter_acm'][hostname]['type'] = 'acm'
        yaml_output['exporter_acm'][hostname]['location'] = location
        yaml_output['exporter_acm'][hostname]['country'] = country
        yaml_output['exporter_acm'][hostname]['username'] = ssh_username
        yaml_output['exporter_acm'][hostname]['password'] = ssh_password

        new_entries.append(row)

    # Load existing YAML data
    existing_yaml_output = load_existing_yaml(output_path)
    # Sort the YAML data by hostname before writing it to the output file
    sorted_yaml_output = OrderedDict(sorted(yaml_output['exporter_acm'].items(), key=lambda x: x[0]))
    # Write the YAML data to a file, either updating the existing file or creating a new file
    process_exporter('exporter_acm', existing_yaml_output, new_entries, yaml_output, output_path)

################################################################## WEBLM_EXPORTER ##############################################################################

def exporter_weblm(file_path, output_file, existing_yaml_file=None):
    global default_listen_port
    global output_path
    new_entries = []
    sorted_yaml_output = []
    output_dir = tempfile.gettempdir()
    output_path = os.path.join(output_dir, output_file)
    
    try:
        flash("Exporter Weblm called")

        df = read_input_file(file_path)

    except Exception as e:
        flash(f"Error: {e}")
        return

    df_filtered = filter_rows_by_exporter(df, 'exporter_weblm')

    if df_filtered.empty:
        print("No rows matching exporter_weblm condition found")
        return

    output_path = os.path.join(output_dir, output_file)

    hostname = df_filtered['FQDN'].iloc[0]

    # Initialize exporter_weblm key in the YAML dictionary
    yaml_output['exporter_weblm'][hostname] = OrderedDict()

    # Iterate over rows in filtered dataframe
    new_entries = []
    for index, row in df_filtered.iterrows():
        ip_address = row['IP Address']
        location = row['Location']
        country = row['Country']
        listen_port = row['App-Listen-Port']
        ssh_username = row.get('ssh_username', 'put your username here')
        ssh_password = row.get('ssh_password', 'put your password here')

        if ip_exists_in_yaml('exporter_weblm', ip_address, output_dir=output_dir, output_file=output_file):
            continue

        yaml_output['exporter_weblm'][hostname]['ip_address'] = ip_address
        yaml_output['exporter_weblm'][hostname]['listen_port'] = int(listen_port) if not pd.isna(listen_port) else int(default_listen_port)
        yaml_output['exporter_weblm'][hostname]['location'] = location
        yaml_output['exporter_weblm'][hostname]['country'] = country
        yaml_output['exporter_weblm'][hostname]['data_path'] = '/opt/Avaya/tomcat/webapps/WebLM/data/'
        yaml_output['exporter_weblm'][hostname]['username'] = ssh_username
        yaml_output['exporter_weblm'][hostname]['password'] = ssh_password

        new_entries.append(row)

    # Load existing YAML data
    existing_yaml_output = load_existing_yaml(output_path)  

    process_exporter('exporter_weblm', existing_yaml_output, new_entries, yaml_output, output_path)

######################################################## exporter_generic ###############################################################################

def exporter_generic(exporter_name, file_path, output_file, existing_yaml_file=None):
    global default_listen_port
    global output_path
    new_entries = []
    sorted_yaml_output = []
    output_dir = tempfile.gettempdir()
    output_path = os.path.join(output_dir, output_file)

    try:
        flash(f"Exporter {exporter_name} called")
        df = read_input_file(file_path)

    except Exception as e:
        flash(f"Error: {e}")
        return

    df_filtered = filter_rows_by_exporter(df, exporter_name)
    output_path = os.path.join(output_dir, output_file)

    yaml_output = {exporter_name: {}}

    for index, row in df_filtered.iterrows():
        process_row_generic(exporter_name, row, yaml_output, default_listen_port)

    new_entries = df_filtered.to_dict('records')
    existing_yaml_output = load_existing_yaml(output_path)

    # Write the YAML data to a file, either updating the existing file or creating a new file
    process_exporter(exporter_name, existing_yaml_output, new_entries, yaml_output, output_path)


###########################################################   process_row_generic   ###################################################################

def process_row_generic(exporter_name, row, yaml_output, default_listen_port, existing_yaml):
    hostname = row['Hostnames']
    ip_address = row['IP Address']
    location = row['Location']
    country = row['Country']

    if ip_exists_in_yaml(exporter_name, ip_address, existing_yaml):
        return

    if hostname not in yaml_output[exporter_name]:
        yaml_output[exporter_name][hostname] = OrderedDict()

    # Use default_listen_port if 'App-Listen-Port' is not available
    listen_port = row.get('App-Listen-Port', default_listen_port)
    if listen_port == default_listen_port:
        default_listen_port += 1

    yaml_output[exporter_name][hostname]['ip_address'] = ip_address
    yaml_output[exporter_name][hostname]['listen_port'] = listen_port
    yaml_output[exporter_name][hostname]['location'] = location
    yaml_output[exporter_name][hostname]['country'] = country

    ssh_username_present = 'ssh_username' in row
    ssh_password_present = 'ssh_password' in row

    # Use the values from the optional headers if present, otherwise use the placeholders
    if ssh_username_present and not pd.isna(row['ssh_username']):
        yaml_output[exporter_name][hostname]['username'] = row['ssh_username']
    else:
        yaml_output[exporter_name][hostname]['username'] = 'root'

    if ssh_password_present and not pd.isna(row['ssh_password']):
        yaml_output[exporter_name][hostname]['password'] = row['ssh_password']
    else:
        yaml_output[exporter_name][hostname]['password'] = 'ENC'


#####################################################   filter_rows_by_exporter   ################################################################

def filter_rows_by_exporter(df, exporter_name):
    os_exporters = ['exporter_linux', 'exporter_windows', 'exporter_verint', 'exporter_vmware']
    
    if exporter_name in os_exporters:
        column_name = 'Exporter_name_os'
    else:
        column_name = 'Exporter_name_app'
    
    return df[df[column_name] == exporter_name]

#####################################################     read input file    ##########################################################################

def read_input_file(file_path):
    # Check if file is CSV or Excel
    file_extension = os.path.splitext(file_path)[1]
    if file_extension == '.csv':
        # Read CSV file into pandas
        df = pd.read_csv(file_path, skiprows=7)
    elif file_extension in ['.xlsx', '.xls']:
        # Read Excel file into pandas
        df = pd.read_excel(file_path, sheet_name='Sheet2', skiprows=range(0, 6))
    else:
        raise ValueError("Invalid file type. Only CSV and Excel files are supported.")
    return df

################################################### write to Yaml file and print.F   #################################################################

def process_exporter(exporter_name, existing_yaml_output, new_entries, yaml_output, output_path):
    # Write the YAML data to a file, either updating the existing file or creating a new file
    if new_entries:
        # Sort the YAML data by hostname before writing it to the output file
        sorted_yaml_output = OrderedDict(sorted(yaml_output.items(), key=lambda x: x[0]))
        # write to the output file
        write_yaml(existing_yaml_output, sorted_yaml_output, output_path)
        print(f"{exporter_name} completed")
        print(f"Total number of hosts processed: {len(new_entries)}")
    else:
        print(f"{exporter_name} completed - nothing to do")

########################################################## load existing yaml  ###########################################################################

def load_existing_yaml(existing_yaml_file):
    if existing_yaml_file:
        existing_yaml = yaml.safe_load(existing_yaml_file)
        if existing_yaml is None:
            existing_yaml = {}
        return existing_yaml
    else:
        return {}

################################################    Check if IP in Yaml exists in filetered csv  #########################################################

def ip_exists_in_yaml(exporter_name, ip_address, existing_yaml):
    """
    Check if the given IP address already exists in the existing_yaml data for the given exporter
    """
    if existing_yaml is None or exporter_name not in existing_yaml:
        return False

    for hostname, ip_data in existing_yaml[exporter_name].items():
        if 'ip_address' in ip_data and ip_data['ip_address'] == ip_address:
            return True

    return False


######################################################      Write Yaml    ################################################################################

def write_yaml(existing_yaml_output, yaml_output, output_path):
    # Update the existing YAML data with the new entries
    for key, value in yaml_output.items():
        if key not in existing_yaml_output:
            existing_yaml_output[key] = {}
        existing_yaml_output[key].update(value)

    # Write the updated YAML data back to the file
    with open(output_path, 'w', encoding='utf8') as f:
        yaml.dump(existing_yaml_output, f, allow_unicode=True)

########

def dict_representer(dumper, data):
    return dumper.represent_dict(data.items())

def dict_constructor(loader, node):
    return OrderedDict(loader.construct_pairs(node))

yaml.add_representer(OrderedDict, dict_representer)
yaml.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, dict_constructor)

#######################################################   MAIN SECTION  FLASK    ##################################################################################


exporter_functions = {
    'exporter_linux': exporter_linux,
    'exporter_blackbox': exporter_blackbox,
    'exporter_ssl': exporter_ssl,
    'exporter_cms': exporter_cms,
    'exporter_windows': exporter_windows,
    'exporter_avayasbc': exporter_avayasbc,
    'exporter_verint': exporter_verint,
    'exporter_gateway': exporter_gateway,
    'exporter_breeze': exporter_breeze,
    'exporter_sm': exporter_sm,
    'exporter_acm': exporter_acm,
    'exporter_jmx': exporter_jmx,
    'exporter_weblm': exporter_weblm,
    'exporter_vmware': exporter_vmware,
    'exporter_kafka': exporter_kafka,
    'exporter_callback': exporter_callback,
    'exporter_drac': exporter_drac,
    'exporter_genesyscloud': exporter_genesyscloud,
    'exporter_tcti': exporter_tcti
}



app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Handle the form submission
        uploaded_file = request.files.get('file')
        selected_exporters = request.form.getlist('exporters')
        default_listen_port = request.form.get('default_listen_port')
        existing_yaml_file = request.files.get('existing_yaml')

        # Save the uploaded file to a temporary location
        if uploaded_file:
            uploaded_file_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(uploaded_file.filename))
            uploaded_file.save(uploaded_file_path)

        # Process each selected exporter
        for exporter in selected_exporters:
            if exporter in exporter_functions:
                exporter_functions[exporter](uploaded_file_path, 'converted.yaml', existing_yaml_file)
            else:
                print(f"Error: {exporter} not found in exporter_functions")

        # Save the output file to the temporary directory
        output_file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'converted.yaml')

        return render_template('index.html', result_file='converted.yaml')

    return render_template('index.html')

@app.route('/download/<file_name>')
def download(file_name):
    return send_from_directory(app.config['UPLOAD_FOLDER'], file_name, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)

def exporter_sm(input_file, output_file, existing_yaml_file=None):
    exporter_generic('exporter_sm', input_file, output_file, existing_yaml_file)

####################################################    EXPORTER_LINUX    #############################################################

def exporter_linux(input_file, output_file, existing_yaml_file=None):
    exporter_generic('exporter_linux', input_file, output_file, existing_yaml_file)
######################################################  EXPORTER_BlackBox  #############################################################

def exporter_blackbox(input_file, output_file, existing_yaml_file=None):
    global default_listen_port
    global output_path
    yaml_output = OrderedDict([('exporter_blackbox', OrderedDict())])
    try:
        print("Exporter Blackbox called")

        df = read_input_file(file_path)

    except Exception as e:
        print(f"Error: {e}")
        return

    df_filtered = filter_rows_by_exporter(df, 'exporter_blackbox')
    output_path = os.path.join(output_file)

    # Initialize exporter_blackbox key in the YAML dictionary
    yaml_output['exporter_blackbox'] = {}

    # Check if optional headers are present
    ssh_username_present = 'ssh_username' in df.columns
    ssh_password_present = 'ssh_password' in df.columns

    # Iterate over rows in filtered dataframe
    new_entries = []
    for index, row in df.iterrows():
        exporter_name = 'exporter_blackbox'
        hostname = row['FQDN']
        ip_address = row['IP Address']
        location = row['Location']
        country = row['Country']

        if ip_exists_in_yaml(exporter_name, ip_address, output_path=output_path):
            continue

        if hostname not in yaml_output.get(exporter_name, {}):
             yaml_output[exporter_name][hostname] = {}
    
        if ip_address not in yaml_output[exporter_name][hostname]:
             yaml_output[exporter_name][hostname][ip_address] = {}
        
        yaml_output[exporter_name][hostname][ip_address]['location'] = location
        yaml_output[exporter_name][hostname][ip_address]['country'] = country
    
        if row['icmp']:
            yaml_output[exporter_name][hostname][ip_address]['module'] = 'icmp'
        
        if row['ssh-banner']:
            ssh_ip_address = f"{ip_address}:22"
            if ip_exists_in_yaml(exporter_name, ssh_ip_address, output_path=output_path):
                continue
            yaml_output[exporter_name][hostname][ssh_ip_address] = {
                'module': 'ssh_banner',
                'location': location,
                'country': country
            }

        new_entries.append(row)

    # Write the YAML data to a file, either updating the existing file or creating a new file
    output_path = os.path.join(output_dir, output_file)
    existing_yaml_output = load_existing_yaml(output_path)

    process_exporter('exporter_blackbox', exporter_name, existing_yaml_output, yaml_output, output_path)

########################################################  EXPORTER_SSL  ##################################################################

def exporter_ssl(file_path, output_file, output_dir):
    try:
        print("Exporter SSL called")

        # Check if file is CSV or Excel
        file_extension = os.path.splitext(file_path)[1]
        if file_extension == '.csv':
            # Read CSV file into pandas
            df = pd.read_csv(file_path, skiprows=7)
        elif file_extension in ['.xlsx', '.xls']:
            # Read Excel file into pandas
            df = pd.read_excel(file_path, sheet_name='Sheet2', skiprows=7)
        else:
            raise ValueError("Invalid file type. Only CSV and Excel files are supported.")
    except Exception as e:
        print(f"Error: {e}")
        return

    # Filter the data based on the condition
    df_filtered = df[df['Exporter_SSL'] == True]

    # Create an empty dictionary to store the YAML output
    yaml_output = OrderedDict([('exporter_ssl', OrderedDict())])

    # Initialize exporter_ssl key in the YAML dictionary
    yaml_output['exporter_ssl'] = {}

    output_path = os.path.join(output_dir, output_file)

    # Initialize new_entries list
    new_entries = []
    # Loop through the filtered data and add to the dictionary
    for _, row in df_filtered.iterrows():
        exporter_name = 'exporter_ssl'
        fqdn = row['FQDN']
        ip_address = row['IP Address']
        location = row['Location']
        country = row['Country']
        exporter_app = row['Exporter_name_app']

        # Set default listen_port to 443 and change it to 8443 if exporter_ssl is specified
        listen_port = 8443 if exporter_app == 'exporter_ssl' else 443

        # Check for duplicate entries
        if ip_exists_in_yaml(exporter_name, ip_address, output_path):
            continue

        if exporter_name not in yaml_output:
            yaml_output[exporter_name] = {}
        if fqdn not in yaml_output[exporter_name]:
            yaml_output[exporter_name][fqdn] = {}
        yaml_output[exporter_name][fqdn] = {
            'ip_address': ip_address,
            'listen_port': listen_port,
            'location': location,
            'country': country,
        }

        new_entries.append(row)

    # Add this line to load existing YAML data
    existing_yaml_output = load_existing_yaml(output_path)  
    # Write the YAML data to a file, either appending to an existing file or creating a new file
    process_exporter('exporter_ssl', existing_yaml_output, new_entries, yaml_output, output_path)

##############################################################   exporter_WINDOWS   ########################################################
   
def exporter_windows(file_path, output_file, output_dir):
    global default_listen_port
    global output_path
    try:
        print("Exporter Windows called")

        df = read_input_file(file_path)

    except Exception as e:
        print(f"Error: {e}")
        return

    df_filtered = filter_rows_by_exporter(df, 'exporter_windows')
    output_path = os.path.join(output_dir, output_file)

    # Initialize exporter_windows key in the YAML dictionary
    yaml_output = OrderedDict([('exporter_windows', OrderedDict())])

    # Iterate over rows in filtered dataframe
    new_entries = []
    for index, row in df_filtered.iterrows():
        exporter_name = 'exporter_windows'
        fqdn = row['FQDN']
        ip_address = row['IP Address']
        location = row['Location']
        country = row['Country']

        if ip_exists_in_yaml(exporter_name, ip_address, output_path=output_path):
            continue

        if fqdn not in yaml_output[exporter_name]:
            yaml_output[exporter_name][fqdn] = {}

        yaml_output[exporter_name][fqdn]['ip_address'] = ip_address
        yaml_output[exporter_name][fqdn]['listen_port'] = 9182  # Set to default listen port for Windows
        yaml_output[exporter_name][fqdn]['location'] = location
        yaml_output[exporter_name][fqdn]['country'] = country

        new_entries.append(row)

    existing_yaml_output = load_existing_yaml(output_path)

    # Write the YAML data to a file, either updating the existing file or creating a new file
    process_exporter('exporter_windows', existing_yaml_output, new_entries, yaml_output, output_path)
  
 ##########################################################   exporter_VERINT   ###############################################################

def exporter_verint(file_path, output_file, output_dir):
    global default_listen_port
    global output_path
    yaml_output = OrderedDict([('exporter_verint', OrderedDict())])
    try:
        print("Exporter Verint called")

        df = read_input_file(file_path)

    except Exception as e:
        print(f"Error: {e}")
        return

    df_filtered = filter_rows_by_exporter(df, 'exporter_verint')
    output_path = os.path.join(output_dir, output_file)

    # Iterate over rows in filtered dataframe
    new_entries = []
    for index, row in df_filtered.iterrows():
        exporter_name = 'exporter_verint'
        fqdn = row['FQDN']
        ip_address = row['IP Address']
        location = row['Location']
        country = row['Country']

        if ip_exists_in_yaml(exporter_name, ip_address, output_path=output_path):
            continue

        if fqdn not in yaml_output[exporter_name]:
            yaml_output[exporter_name][fqdn] = {}

        yaml_output[exporter_name][fqdn]['ip_address'] = ip_address
        yaml_output[exporter_name][fqdn]['listen_port'] = 9182
        yaml_output[exporter_name][fqdn]['location'] = location
        yaml_output[exporter_name][fqdn]['country'] = country

        new_entries.append(row)

    existing_yaml_output = load_existing_yaml(output_path)

    # Write the YAML data to a file, either updating the existing file or creating a new file
    process_exporter('exporter_verint', existing_yaml_output, new_entries, yaml_output, output_path)
               
#######################################################   AVAYA SBC   ####################################################################

def exporter_avayasbc(file_path, output_file, output_dir):
    global default_listen_port
    global output_path
    yaml_output = {'exporter_avayasbc': {}}
    try:
        print("Exporter SBC called")

        df = read_input_file(file_path)

    except Exception as e:
        print(f"Error: {e}")
        return

    df_filtered = filter_rows_by_exporter(df, 'exporter_avayasbc')
    output_path = os.path.join(output_dir, output_file)

    # Initialize exporter_avayasbc key in the YAML dictionary
    yaml_output = OrderedDict([('exporter_avayasbc', OrderedDict())])

    # Iterate over rows in filtered dataframe
    new_entries = []
    for index, row in df_filtered.iterrows():
        exporter_name = 'exporter_avayasbc'
        hostname = row['FQDN']
        ip_address = row['IP Address']
        location = row['Location']
        country = row['Country']

        if ip_exists_in_yaml(exporter_name, ip_address, output_path=output_path):
            continue

        if hostname not in yaml_output[exporter_name]:
            yaml_output[exporter_name][hostname] = {}

        if ip_address not in yaml_output[exporter_name][hostname]:
            yaml_output[exporter_name][hostname][ip_address] = {}

            yaml_output[exporter_name][hostname][ip_address]['listen_port'] = 3601
            yaml_output[exporter_name][hostname][ip_address]['location'] = location
            yaml_output[exporter_name][hostname][ip_address]['country'] = country
            yaml_output[exporter_name][hostname][ip_address]['username'] = 'ipcs'

            new_entries.append(row)

    # Load existing YAML data
    existing_yaml_output = load_existing_yaml(output_path)  
    # Write the YAML data to a file, either appending to an existing file or creating a new file
    process_exporter('exporter_avayasbc', existing_yaml_output, new_entries, yaml_output, output_path)

###########################################   exporter_GATEWAY   ####################################################################

def exporter_gateway(file_path, output_file, output_dir):
    global default_listen_port
    global output_path

    try:
        print("Exporter Gateway called")

        df = read_input_file(file_path)

    except Exception as e:
        print(f"Error: {e}")
        return

    df_filtered = filter_rows_by_exporter(df, 'exporter_gateway')
    output_path = os.path.join(output_dir, output_file)

    # Initialize exporter_gateway key in the YAML dictionary
    yaml_output = OrderedDict([('exporter_gateway', OrderedDict())])

    # Iterate over rows in filtered dataframe
    new_entries = []
    for index, row in df_filtered.iterrows():
        exporter_name = 'exporter_gateway'
        hostname = row['Hostnames']
        ip_address = row['IP Address']
        location = row['Location']
        country = row['Country']

        if ip_exists_in_yaml(exporter_name, ip_address, output_path=output_path):
            continue

        if hostname not in yaml_output[exporter_name]:
            yaml_output[exporter_name][hostname] = {}

        if ip_address not in yaml_output[exporter_name][hostname]:
            yaml_output[exporter_name][hostname][ip_address] = {}

        if pd.isna(row['App-Listen-Port']):
            yaml_output[exporter_name][hostname][ip_address]['listen_port'] = int(default_listen_port.get())
        else:
            yaml_output[exporter_name][hostname][ip_address]['listen_port'] = int(row['App-Listen-Port'])

        yaml_output[exporter_name][hostname][ip_address]['location'] = location
        yaml_output[exporter_name][hostname][ip_address]['country'] = country
        yaml_output[exporter_name][hostname][ip_address]['snmp_version'] = 2

        if 'comm_string' in df.columns and not pd.isna(row['comm_string']):
            yaml_output[exporter_name][hostname][ip_address]['community'] = row['comm_string']
        else:
            yaml_output[exporter_name][hostname][ip_address]['community'] = 'ENC'

        new_entries.append(row)

    existing_yaml_output = load_existing_yaml(output_path)  # Add this line to load existing YAML data
    # Write the YAML data to a file, either appending to an existing file or creating a new file
    process_exporter('exporter_gateway', existing_yaml_output, new_entries, yaml_output, output_path)

#######################################################  EXPORTER_TCTI       ############################################################

def exporter_tcti(file_path, output_file, output_dir):
    global default_listen_port
    global output_path

    try:
        print("Exporter TCTI called")

        df = read_input_file(file_path)

    except Exception as e:
        print(f"Error: {e}")
        return

    df_filtered = filter_rows_by_exporter(df, 'exporter_tcti')
    output_path = os.path.join(output_dir, output_file)
    yaml_output = OrderedDict([('exporter_tcti', OrderedDict())])

    # Iterate over rows in filtered dataframe
    new_entries = []
    for index, row in df_filtered.iterrows():
        hostname = row['FQDN']
        ip_address = row['IP Address']
        location = row['Location']
        country = row['Country']

        if ip_exists_in_yaml('exporter_tcti', ip_address, output_path=output_path):
            continue

        if hostname not in yaml_output['exporter_tcti']:
            yaml_output['exporter_tcti'][hostname] = {}

        jmx_ports_present = 'jmx_ports' in row.index
        if jmx_ports_present and not pd.isna(row['jmx_ports']) and row['jmx_ports']:
            ports = [int(port) for port in row['jmx_ports'].split(',')]
        else:
            ports = [8080, 8081]

        for port in ports:
            if port not in yaml_output['exporter_tcti'][hostname]:
                yaml_output['exporter_tcti'][hostname][int(port)] = {} # Changed this line

            yaml_output['exporter_tcti'][hostname][int(port)]['ip_address'] = ip_address
            yaml_output['exporter_tcti'][hostname][int(port)]['location'] = location
            yaml_output['exporter_tcti'][hostname][int(port)]['country'] = country
            new_entries.append(row)

    # Add this line to load existing YAML data
    existing_yaml_output = load_existing_yaml(output_path)          
    # Write the YAML data to a file, either updating the existing file or creating a new file
    process_exporter('exporter_tcti', existing_yaml_output, new_entries, yaml_output, output_path)

########################################################## EXPORTER_JMX #####################################################################
def exporter_jmx(file_path, output_file, output_dir):
    global default_listen_port
    global output_path

    try:
        print("Exporter JMX called")

        df = read_input_file(file_path)

    except Exception as e:
        print(f"Error: {e}")
        return

    df_filtered = filter_rows_by_exporter(df, 'exporter_jmx')
    output_path = os.path.join(output_dir, output_file)
    yaml_output = OrderedDict([('exporter_jmx', OrderedDict())])

    # Iterate over rows in filtered dataframe
    new_entries = []
    for index, row in df_filtered.iterrows():
        hostname = row['FQDN']
        ip_address = row['IP Address']
        location = row['Location']
        country = row['Country']

        if ip_exists_in_yaml('exporter_jmx', ip_address, output_path=output_path):
            continue

        if hostname not in yaml_output['exporter_jmx']:
            yaml_output['exporter_jmx'][hostname] = {}

        jmx_ports_present = 'jmx_ports' in row.index
        if jmx_ports_present and not pd.isna(row['jmx_ports']) and row['jmx_ports']:
            ports = [int(port) for port in row['jmx_ports'].split(',')]
        else:
            ports = [8080, 8081]

        for port in ports:
            if port not in yaml_output['exporter_jmx'][hostname]:
                yaml_output['exporter_jmx'][hostname][int(port)] = {} # Changed this line

            yaml_output['exporter_jmx'][hostname][int(port)]['ip_address'] = ip_address
            yaml_output['exporter_jmx'][hostname][int(port)]['location'] = location
            yaml_output['exporter_jmx'][hostname][int(port)]['country'] = country
            new_entries.append(row)

    # Add this line to load existing YAML data
    existing_yaml_output = load_existing_yaml(output_path)          
    # Write the YAML data to a file, either updating the existing file or creating a new file
    process_exporter('exporter_jmx', existing_yaml_output, new_entries, yaml_output, output_path)

######################################################## EXPORTER_VMWARE #######################################################################

def exporter_vmware(file_path, output_file, output_dir):
    global default_listen_port
    global output_path
    yaml_output = OrderedDict([('exporter_vmware', OrderedDict())])
    try:
        print("Exporter vmware called")

        df = read_input_file(file_path)

    except Exception as e:
        print(f"Error: {e}")
        return

    df_filtered = filter_rows_by_exporter(df, 'exporter_vmware')
    output_path = os.path.join(output_dir, output_file)

    # Iterate over rows in filtered dataframe
    new_entries = []
    for index, row in df_filtered.iterrows():
        hostname = row['FQDN']
        ip_address = row['IP Address']
        location = row['Location']
        country = row['Country']

        if ip_exists_in_yaml('exporter_vmware', ip_address, output_path=output_path):
            continue

        if hostname not in yaml_output['exporter_vmware']:
            yaml_output['exporter_vmware'][hostname] = {}

        if pd.isna(row['App-Listen-Port']):
            yaml_output['exporter_vmware'][hostname]['listen_port'] = 9272
        else:
            yaml_output['exporter_vmware'][hostname]['listen_port'] = int(row['App-Listen-Port'])

        yaml_output['exporter_vmware'][hostname]['ip_address'] = ip_address
        yaml_output['exporter_vmware'][hostname]['location'] = location
        yaml_output['exporter_vmware'][hostname]['country'] = country
        yaml_output['exporter_vmware'][hostname]['username'] = 'put your username here'
        yaml_output['exporter_vmware'][hostname]['password'] = 'put your password here'

        new_entries.append(row)

    # Add this line to load existing YAML data
    existing_yaml_output = load_existing_yaml(output_path)  

    # Write the YAML data to a file, either updating the existing file or creating a new file
    process_exporter('exporter_vmware', existing_yaml_output, new_entries, yaml_output, output_path)

################################################################ EXPORTER_KAFKA ###############################################################

def exporter_kafka(file_path, output_file, output_dir):
    global default_listen_port
    global output_path
    new_entries = []

    try:
        print("Exporter Exporter Kafka  called")

        df = read_input_file(file_path)

    except Exception as e:
        print(f"Error: {e}")
        return

    df_filtered = filter_rows_by_exporter(df, 'exporter_kafka')
    output_path = os.path.join(output_dir, output_file)

    if df_filtered.empty:
        print("No rows matching exporter_kafka condition found")
        return

    # Initialize exporter_genesyscloud key in the YAML dictionary
    yaml_output = OrderedDict([('exporter_kafka', OrderedDict())])

    # Iterate over rows in filtered dataframe
    new_entries = []
    for index, row in df.iterrows():
        hostname = row['FQDN']
        ip_address = row['IP Address']
        location = row['Location']
        country = row['Country']

        output_path = os.path.join(output_dir, output_file)
        if ip_exists_in_yaml('exporter_kafka', ip_address, output_path=output_path):
            continue

        if hostname not in yaml_output.get('exporter_kafka', {}):
            yaml_output['exporter_kafka'][hostname] = {}

        yaml_output['exporter_kafka'][hostname]['ip_address'] = ip_address
        yaml_output['exporter_kafka'][hostname]['listen_port'] = int(row['App-Listen-Port'])
        yaml_output['exporter_kafka'][hostname]['location'] = location
        yaml_output['exporter_kafka'][hostname]['country'] = country
        yaml_output['exporter_kafka'][hostname]['kafka_port'] = 9092

        new_entries.append(row)

    # Add this line to load existing YAML data
    existing_yaml_output = load_existing_yaml(output_path)  

    # Write the YAML data to a file, either updating the existing file or creating a new file
    process_exporter('exporter_kafka', existing_yaml_output, new_entries, yaml_output, output_path)

############################################################ EXPORTER_DRAC ############################################################################

def exporter_drac(file_path, output_file, output_dir):
    global default_listen_port
    global output_path

    # Initialize exporter_kafka key in the YAML dictionary
    yaml_output = {'exporter_drac': {}}

    try:
        print("Exporter DRAC called")

        df = read_input_file(file_path)

    except Exception as e:
        print(f"Error: {e}")
        return

    df_filtered = filter_rows_by_exporter(df, 'exporter_drac')
    output_path = os.path.join(output_dir, output_file)

    # Initialize exporter_drac key in the YAML dictionary
    yaml_output = OrderedDict([('exporter_drac', OrderedDict())])

    # Iterate over rows in filtered dataframe
    new_entries = []
    for index, row in df_filtered.iterrows():
        hostname = row['FQDN']
        ip_address = row['IP Address']
        location = row['Location']
        country = row['Country']

        if ip_exists_in_yaml('exporter_drac', ip_address, output_path=output_path):
            continue

        if hostname not in yaml_output['exporter_drac']:
            yaml_output['exporter_drac'][hostname] = {}

        yaml_output['exporter_drac'][hostname]['ip_address'] = ip_address
        yaml_output['exporter_drac'][hostname]['listen_port'] = 623
        yaml_output['exporter_drac'][hostname]['location'] = location
        yaml_output['exporter_drac'][hostname]['country'] = country
        yaml_output['exporter_drac'][hostname]['snmp_version'] = 2
        yaml_output['exporter_drac'][hostname]['community'] = row.get('comm_string', 'ENC')

        new_entries.append(row)

    # Add this line to load existing YAML data
    existing_yaml_output = load_existing_yaml(output_path)  

    # Write the YAML data to a file, either updating the existing file or creating a new file
    process_exporter('exporter_drac', existing_yaml_output, new_entries, yaml_output, output_path)

##################################################### exporter_genesyscloud ##########################################################################

def exporter_genesyscloud(file_path, output_file, output_dir):
    global default_listen_port
    global output_path
    new_entries = []
    sorted_yaml_output =[]
    try:
        print("Exporter Genesys Cloud called")

        df = read_input_file(file_path)

    except Exception as e:
        print(f"Error: {e}")
        return

    df_filtered = filter_rows_by_exporter(df, 'exporter_genesyscloud')
    output_path = os.path.join(output_dir, output_file)

    if df_filtered.empty:
        print("No rows matching exporter_genesyscloud condition found")
        return

    # Initialize exporter_genesyscloud key in the YAML dictionary
    yaml_output = OrderedDict([('exporter_genesyscloud', OrderedDict())])

    # Iterate over rows in filtered dataframe
    new_entries = []
    for index, row in df.iterrows():
        hostname = row['FQDN']
        listen_port = row['App-Listen-Port']
        ip_address = row['IP Address']
        location = row['Location']
        country = row['Country']
        comm_string = row.get('comm_string', 'public')


        if ip_exists_in_yaml('exporter_genesyscloud', ip_address, output_path=output_path):
            continue

        yaml_output['exporter_genesyscloud'][hostname] = OrderedDict([
            ('listen_port', listen_port),
            ('extra_args', (" --client.managed  --billing.enabled --billing.frequency 30m --usage.enabled "
                          "--usage.frequency 12h --client.first-day-of-month 22 --mos.enabled "
                          "--mos.bandceilingcritical 2.59999 --mos.bandceilingbad 3.59999 "
                          "--mos.bandceilingwarning 3.09999 --mos.bandceilinggood 3.99999")),
            ('client_id', 'ENC[PKCS7...]'),
            ('client_secret', 'ENC[PKCS7...]'),
            ('client_basepath', 'https://api.mypurecloud.ie'),
            ('ip_address', ip_address),
            ('location', location),
            ('country', country),
            ('community', comm_string)
        ])

        new_entries.append(row)

    # Add this line to load existing YAML data
    existing_yaml_output = load_existing_yaml(output_path)  
    # Sort the YAML data by hostname before writing it to the output file
    sorted_yaml_output = OrderedDict(sorted(yaml_output['exporter_genesyscloud'].items(), key=lambda x: x[0]))
    # Write the YAML data to a file, either updating the existing file or creating a new file
    process_exporter('exporter_genesyscloud', existing_yaml_output, new_entries, yaml_output, output_path)

################################################################### EXPORTER_ACM #####################################################################

def exporter_acm(file_path, output_file, output_dir):
    global default_listen_port
    global output_path
    new_entries = []
    sorted_yaml_output =[]
    try:
        print("Exporter ACM called")

        df = read_input_file(file_path)

    except Exception as e:
        print(f"Error: {e}")
        return

    df_filtered = filter_rows_by_exporter(df, 'exporter_acm')
    output_path = os.path.join(output_dir, output_file)

    if df_filtered.empty:
        print("No rows matching exporter_acm condition found")
        return

    # Initialize exporter_acm key in the YAML dictionary
    yaml_output = OrderedDict([('exporter_acm', OrderedDict())])

    for index, row in df_filtered.iterrows():
        hostname = row['FQDN']
        ip_address = row['IP Address']
        location = row['Location']
        country = row['Country']
        listen_port = row['App-Listen-Port']
        ssh_username = row.get('ssh_username', 'put your username here')
        ssh_password = row.get('ssh_password', 'put your password here')

        if ip_exists_in_yaml('exporter_acm', ip_address, output_path=output_path):
            print(f"IP {ip_address} already exists in the YAML file.")
            continue

        if hostname not in yaml_output.get('exporter_acm', {}):
            yaml_output['exporter_acm'][hostname] = OrderedDict()

        yaml_output['exporter_acm'][hostname]['ip_address'] = ip_address
        yaml_output['exporter_acm'][hostname]['listen_port'] = int(listen_port) if not pd.isna(listen_port) else int(default_listen_port)
        if 'lsp' in hostname.lower():
            yaml_output['exporter_acm'][hostname]['type'] = 'lsp'
        elif 'ess' in hostname.lower():
            yaml_output['exporter_acm'][hostname]['type'] = 'ess'
        else:
            yaml_output['exporter_acm'][hostname]['type'] = 'acm'
        yaml_output['exporter_acm'][hostname]['location'] = location
        yaml_output['exporter_acm'][hostname]['country'] = country
        yaml_output['exporter_acm'][hostname]['username'] = ssh_username
        yaml_output['exporter_acm'][hostname]['password'] = ssh_password

        new_entries.append(row)

    # Load existing YAML data
    existing_yaml_output = load_existing_yaml(output_path)
    # Sort the YAML data by hostname before writing it to the output file
    sorted_yaml_output = OrderedDict(sorted(yaml_output['exporter_acm'].items(), key=lambda x: x[0]))
    # Write the YAML data to a file, either updating the existing file or creating a new file
    process_exporter('exporter_acm', existing_yaml_output, new_entries, yaml_output, output_path)

################################################################## WEBLM_EXPORTER ##############################################################################

def exporter_weblm(file_path, output_file, output_dir):
    global default_listen_port
    global output_path

    try:
        print("Exporter Weblm called")

        df = read_input_file(file_path)

    except Exception as e:
        print(f"Error: {e}")
        return

    df_filtered = filter_rows_by_exporter(df, 'exporter_weblm')

    if df_filtered.empty:
        print("No rows matching exporter_weblm condition found")
        return

    output_path = os.path.join(output_dir, output_file)

    hostname = df_filtered['FQDN'].iloc[0]

    # Initialize exporter_weblm key in the YAML dictionary
    yaml_output['exporter_weblm'][hostname] = OrderedDict()

    # Iterate over rows in filtered dataframe
    new_entries = []
    for index, row in df_filtered.iterrows():
        ip_address = row['IP Address']
        location = row['Location']
        country = row['Country']
        listen_port = row['App-Listen-Port']
        ssh_username = row.get('ssh_username', 'put your username here')
        ssh_password = row.get('ssh_password', 'put your password here')

        if ip_exists_in_yaml('exporter_weblm', ip_address, output_dir=output_dir, output_file=output_file):
            continue

        yaml_output['exporter_weblm'][hostname]['ip_address'] = ip_address
        yaml_output['exporter_weblm'][hostname]['listen_port'] = int(listen_port) if not pd.isna(listen_port) else int(default_listen_port)
        yaml_output['exporter_weblm'][hostname]['location'] = location
        yaml_output['exporter_weblm'][hostname]['country'] = country
        yaml_output['exporter_weblm'][hostname]['data_path'] = '/opt/Avaya/tomcat/webapps/WebLM/data/'
        yaml_output['exporter_weblm'][hostname]['username'] = ssh_username
        yaml_output['exporter_weblm'][hostname]['password'] = ssh_password

        new_entries.append(row)

    # Load existing YAML data
    existing_yaml_output = load_existing_yaml(output_path)  

    process_exporter('exporter_weblm', existing_yaml_output, new_entries, yaml_output, output_path)

######################################################## exporter_generic ###############################################################################

def exporter_generic(exporter_name, file_path, output_file, output_dir):
    global default_listen_port
    global output_path

    try:
        print(f"Exporter {exporter_name} called")
        df = read_input_file(file_path)

    except Exception as e:
        print(f"Error: {e}")
        return

    df_filtered = filter_rows_by_exporter(df, exporter_name)
    output_path = os.path.join(output_dir, output_file)

    yaml_output = {exporter_name: {}}

    for index, row in df_filtered.iterrows():
        process_row_generic(exporter_name, row, yaml_output, default_listen_port)

    new_entries = df_filtered.to_dict('records')
    existing_yaml_output = load_existing_yaml(output_path)

    # Write the YAML data to a file, either updating the existing file or creating a new file
    process_exporter(exporter_name, existing_yaml_output, new_entries, yaml_output, output_path)

###########################################################   process_row_generic   ###################################################################

def process_row_generic(exporter_name, row, yaml_output, default_listen_port, existing_yaml):
    hostname = row['Hostnames']
    ip_address = row['IP Address']
    location = row['Location']
    country = row['Country']

    if ip_exists_in_yaml(exporter_name, ip_address, existing_yaml):
        return

    if hostname not in yaml_output[exporter_name]:
        yaml_output[exporter_name][hostname] = OrderedDict()

    # Use default_listen_port if 'App-Listen-Port' is not available
    listen_port = row.get('App-Listen-Port', default_listen_port)
    if listen_port == default_listen_port:
        default_listen_port += 1

    yaml_output[exporter_name][hostname]['ip_address'] = ip_address
    yaml_output[exporter_name][hostname]['listen_port'] = listen_port
    yaml_output[exporter_name][hostname]['location'] = location
    yaml_output[exporter_name][hostname]['country'] = country

    ssh_username_present = 'ssh_username' in row
    ssh_password_present = 'ssh_password' in row

    # Use the values from the optional headers if present, otherwise use the placeholders
    if ssh_username_present and not pd.isna(row['ssh_username']):
        yaml_output[exporter_name][hostname]['username'] = row['ssh_username']
    else:
        yaml_output[exporter_name][hostname]['username'] = 'root'

    if ssh_password_present and not pd.isna(row['ssh_password']):
        yaml_output[exporter_name][hostname]['password'] = row['ssh_password']
    else:
        yaml_output[exporter_name][hostname]['password'] = 'ENC'


#####################################################   filter_rows_by_exporter   ################################################################

def filter_rows_by_exporter(df, exporter_name):
    os_exporters = ['exporter_linux', 'exporter_windows', 'exporter_verint', 'exporter_vmware']
    
    if exporter_name in os_exporters:
        column_name = 'Exporter_name_os'
    else:
        column_name = 'Exporter_name_app'
    
    return df[df[column_name] == exporter_name]

#####################################################     read input file    ##########################################################################

def read_input_file(file_path):
    # Check if file is CSV or Excel
    file_extension = os.path.splitext(file_path)[1]
    if file_extension == '.csv':
        # Read CSV file into pandas
        df = pd.read_csv(file_path, skiprows=7)
    elif file_extension in ['.xlsx', '.xls']:
        # Read Excel file into pandas
        df = pd.read_excel(file_path, sheet_name='Sheet2', skiprows=range(0, 6))
    else:
        raise ValueError("Invalid file type. Only CSV and Excel files are supported.")
    return df

################################################### write to Yaml file and print.F   #################################################################

def process_exporter(exporter_name, existing_yaml_output, new_entries, yaml_output, output_path):
    # Write the YAML data to a file, either updating the existing file or creating a new file
    if new_entries:
        # Sort the YAML data by hostname before writing it to the output file
        sorted_yaml_output = OrderedDict(sorted(yaml_output.items(), key=lambda x: x[0]))
        # write to the output file
        write_yaml(existing_yaml_output, sorted_yaml_output, output_path)
        print(f"{exporter_name} completed")
        print(f"Total number of hosts processed: {len(new_entries)}")
    else:
        print(f"{exporter_name} completed - nothing to do")

########################################################## load existing yaml  ###########################################################################

def load_existing_yaml(existing_yaml_file):
    if existing_yaml_file:
        existing_yaml = yaml.safe_load(existing_yaml_file)
        if existing_yaml is None:
            existing_yaml = {}
        return existing_yaml
    else:
        return {}

################################################    Check if IP in Yaml exists in filetered csv  #########################################################

def ip_exists_in_yaml(exporter_name, ip_address, existing_yaml):
    """
    Check if the given IP address already exists in the existing_yaml data for the given exporter
    """
    if existing_yaml is None or exporter_name not in existing_yaml:
        return False

    for hostname, ip_data in existing_yaml[exporter_name].items():
        if 'ip_address' in ip_data and ip_data['ip_address'] == ip_address:
            return True

    return False


######################################################      Write Yaml    ################################################################################

def write_yaml(existing_yaml_output, yaml_output, output_path):
    # Update the existing YAML data with the new entries
    for key, value in yaml_output.items():
        if key not in existing_yaml_output:
            existing_yaml_output[key] = {}
        existing_yaml_output[key].update(value)

    # Write the updated YAML data back to the file
    with open(output_path, 'w', encoding='utf8') as f:
        yaml.dump(existing_yaml_output, f, allow_unicode=True)

########

def dict_representer(dumper, data):
    return dumper.represent_dict(data.items())

def dict_constructor(loader, node):
    return OrderedDict(loader.construct_pairs(node))

yaml.add_representer(OrderedDict, dict_representer)
yaml.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, dict_constructor)

#######################################################   MAIN SECTION  FLASK    ##################################################################################


exporter_functions = {
    'exporter_linux': exporter_linux,
    'exporter_blackbox': exporter_blackbox,
    'exporter_ssl': exporter_ssl,
    'exporter_cms': exporter_cms,
    'exporter_windows': exporter_windows,
    'exporter_avayasbc': exporter_avayasbc,
    'exporter_verint': exporter_verint,
    'exporter_gateway': exporter_gateway,
    'exporter_breeze': exporter_breeze,
    'exporter_sm': exporter_sm,
    'exporter_acm': exporter_acm,
    'exporter_jmx': exporter_jmx,
    'exporter_weblm': exporter_weblm,
    'exporter_vmware': exporter_vmware,
    'exporter_kafka': exporter_kafka,
    'exporter_callback': exporter_callback,
    'exporter_drac': exporter_drac,
    'exporter_genesyscloud': exporter_genesyscloud,
    'exporter_tcti': exporter_tcti
}



app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Handle the form submission
        uploaded_file = request.files.get('file')
        selected_exporters = request.form.getlist('exporters')
        default_listen_port = request.form.get('default_listen_port')
        existing_yaml_file = request.files.get('existing_yaml')

        # Process each selected exporter
        for exporter in selected_exporters:
            if exporter == 'exporter_linux':
                exporter_linux(uploaded_file, 'converted.yaml', existing_yaml_file)
            elif exporter == 'exporter_blackbox':
                exporter_blackbox(uploaded_file, 'converted.yaml', existing_yaml_file)
            # Add other exporter functions here

        # Save the output file to the temporary directory
        output_file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'converted.yaml')

        return render_template('index.html', result_file='converted.yaml')

    return render_template('index.html')

@app.route('/download/<file_name>')
def download(file_name):
    return send_from_directory(app.config['UPLOAD_FOLDER'], file_name, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
