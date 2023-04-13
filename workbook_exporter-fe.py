from flask import Flask, request, jsonify, send_from_directory
import pandas as pd
import yaml
import os

app = Flask(__name__)

@app.route('/')
def index():
    return '''
        <form method="post" action="/convert">
            <label for="file_path">File path:</label>
            <input type="text" name="file_path" required><br>
            <label for="output_file">Output file name:</label>
            <input type="text" name="output_file" required><br>
            <label for="output_dir">Output directory:</label>
            <input type="text" name="output_dir" required><br>
            <label for="listen_port">Listen port:</label>
            <input type="text" name="listen_port" value="5000"><br>
            <label for="exporter_name">Exporter:</label>
            <select name="exporter_name" multiple>
                <option value="exporter_blackbox">Exporter Blackbox</option>
                <option value="exporter_linux">Exporter Linux</option>
                <option value="exporter_windows">Exporter Windows</option>
            </select><br>
            <input type="submit" value="Convert">
        </form>
    '''

@app.route('/convert', methods=['POST'])
def convert():
    # Get file path, output file name, and output directory from form data
    file_path = request.form['file_path']
    output_file = request.form['output_file']
    output_dir = request.form['output_dir']
    listen_port = request.form.get('listen_port', '5000')
    exporter_name = request.form.getlist('exporter_name')
    
    # Read CSV file into pandas DataFrame
    df = pd.read_csv(file_path)

    # Create an empty dictionary to hold the final YAML data
    yaml_data = {}

    # Loop through each exporter selected in the form
    for exporter in exporter_name:
        # Filter the data based on the exporter condition
        df_filtered = df[df['Exporter_name_os'] == exporter]

        # Convert the filtered DataFrame to a dictionary
        data_dict = df_filtered.to_dict(orient='records')

        # Add the data to the YAML dictionary with the exporter name as the key
        yaml_data[exporter] = data_dict

    # Write the YAML data to a file
    output_path = os.path.join(output_dir, output_file)
    with open(output_path, 'w') as f:
        yaml.dump(yaml_data, f)

    # Return a link to download the file
    return f'File saved to <a href="/download/{output_file}">{output_file}</a>'

@app.route('/download/<path:path>')
def download(path):
    # Return the file in the output directory as a download
    return send_from_directory('output', path, as_attachment=True)

if __name__ == '__main__':
    app.run(port=listen_port)
