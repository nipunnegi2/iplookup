# app.py
from flask import Flask, render_template, request, jsonify
import requests
from datetime import datetime

app = Flask(__name__)

class IPLookup:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'Accept': 'application/rdap+json',
            'User-Agent': 'IPLookupTool/1.0'
        })

    def get_ip_info(self, ip_address):
        try:
            # Try ARIN first
            response = self.session.get(f'https://rdap.arin.net/registry/ip/{ip_address}')
            
            if response.status_code == 302 or response.status_code == 404:
                other_rdap_servers = [
                    'https://rdap.apnic.net/ip/',
                    'https://rdap.ripe.net/ip/',
                    'https://rdap.lacnic.net/rdap/ip/',
                    'https://rdap.afrinic.net/rdap/ip/'
                ]
                
                for server in other_rdap_servers:
                    response = self.session.get(f'{server}{ip_address}')
                    if response.status_code == 200:
                        break
            
            if response.status_code != 200:
                return {'error': f"Unable to fetch information for IP {ip_address}"}

            data = response.json()
            return self.parse_data(data)

        except requests.exceptions.RequestException as e:
            return {'error': str(e)}

    def parse_data(self, data):
        result = {
            'network': {
                'range': f"{data.get('startAddress', 'N/A')} - {data.get('endAddress', 'N/A')}",
                'source_registry': data.get('port43', '').split('.')[1].upper() if 'port43' in data else 'N/A',
                'net_range': f"{data.get('startAddress', 'N/A')} - {data.get('endAddress', 'N/A')}",
                'cidr': ', '.join([f"{cidr['v4prefix']}/{cidr['length']}" for cidr in data.get('cidr0_cidrs', [])]) if 'cidr0_cidrs' in data else 'N/A',
                'name': data.get('name', '*not provided*'),
                'handle': data.get('handle', '*not provided*'),
                'parent': '*not provided*',
                'net_type': data.get('type', '*not provided*'),
                'origin_as': '*not provided*'
            },
            'dates': {
                'registration': None,
                'last_changed': None
            },
            'description': data.get('remarks', [{'description': ['*not provided*']}])[0]['description'][0],
            'links': {
                'self': data.get('links', [{'href': '*not provided*'}])[0].get('href', '*not provided*'),
                'related': '*not provided*',
                'port43_whois': data.get('port43', '*not provided*')
            },
            'entities': []
        }

        # Handle events/dates
        if 'events' in data:
            for event in data['events']:
                if event['eventAction'] == 'registration':
                    result['dates']['registration'] = event['eventDate']
                elif event['eventAction'] == 'last changed':
                    result['dates']['last_changed'] = event['eventDate']

        # Process entities
        if 'entities' in data:
            for entity in data['entities']:
                entity_data = {
                    'kind': entity.get('handle', '*not provided*'),
                    'full_name': '*not provided*',
                    'handle': entity.get('handle', '*not provided*'),
                    'email': [],
                    'telephone': [],
                    'address': '*not provided*',
                    'roles': entity.get('roles', []),
                    'registration': '*not provided*',
                    'last_changed': '*not provided*',
                    'remarks': '*not provided*',
                    'self': entity.get('links', [{'href': '*not provided*'}])[0].get('href', '*not provided*'),
                    'port43_whois': '*not provided*'
                }

                if 'vcardArray' in entity:
                    vcard = entity['vcardArray'][1]
                    for item in vcard:
                        if item[0] == 'fn':
                            entity_data['full_name'] = item[3]
                        elif item[0] == 'email':
                            entity_data['email'].append(item[3])
                        elif item[0] == 'tel':
                            entity_data['telephone'].append(item[3])
                        elif item[0] == 'adr':
                            entity_data['address'] = ', '.join(filter(None, item[3]))

                if 'events' in entity:
                    for event in entity['events']:
                        if event['eventAction'] == 'registration':
                            entity_data['registration'] = event['eventDate']
                        elif event['eventAction'] == 'last changed':
                            entity_data['last_changed'] = event['eventDate']

                if 'remarks' in entity:
                    entity_data['remarks'] = entity['remarks'][0]['description'][0]

                result['entities'].append(entity_data)

        return result

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/lookup', methods=['POST'])
def lookup():
    ip_address = request.form.get('ip')
    if not ip_address:
        return jsonify({'error': 'No IP address provided'})
    
    ip_lookup = IPLookup()
    result = ip_lookup.get_ip_info(ip_address)
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)