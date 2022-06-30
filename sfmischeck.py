from log import log_message, log_vulnerability
from sf import SFExploit
from datetime import date
from termcolor import colored
import sys
import os
import json

def salesforce_tester(url, token, proxy):
	log_message(f"> Testing: {url}")
	vulnerability = {'accessible_objects_unauth':[],
					'writable_objects_unauth':[], 'update_record_unauth':[], 'delete_record_unauth':[], 'accessible_objects_auth':[], 'writable_objects_auth':[], 'update_record_auth':[], 'delete_record_auth':[]}
	got_objects = list()
	available_objects = open("standard_objects.txt", "r").read().split("\n")
	unauth_tester = SFExploit(url, proxy=proxy)
	auth_tester = None
	if token != "undefined":
		auth_tester = SFExploit(url, token=token, proxy=proxy)
	if unauth_tester.invalid:
		return {'vulnerable':False}
	available_objects_temp = unauth_tester.get_objects()
	available_objects = list(set(available_objects+available_objects_temp))
	if auth_tester:
		available_objects_temp = auth_tester.get_objects()
		available_objects = list(set(available_objects+available_objects_temp))

	# test unauth object access
	log_message(f">> Testing unauth objects.")
	for object_name in available_objects:
		object_data, record_id = unauth_tester.get_object_items(object_name)
		if object_data: # something was returned:
			log_vulnerability(f">>> Found {object_name} to be accessible.")
			object_data_metric = {object_name:{'total_count':object_data['totalCount']}}
			vulnerability['accessible_objects_unauth'].append(object_data_metric)
			got_objects.append(object_name)
			log_message(f">> Testing unauth update/delete record of object {object_name}")
			r = unauth_tester.attempt_record_update(object_name, record_id)
			if r:
				log_vulnerability(f">>> Found record of {object_name} could be updated.")
				vulnerability['update_record_unauth'].append(object_name)
			r = unauth_tester.attempt_record_delete(record_id)
			if r:
				log_vulnerability(f">>> Found record of {object_name} could be deleted.")
				vulnerability['delete_record_unauth'].append(object_name)
			if object_name == "CollaborationGroup" and record_id:
					r = unauth_tester.get_collab_feeds(record_id)
					if r:
						log_vulnerability(f">>> Found collab feeds of {object_name} could be extracted.")
					r = unauth_tester.ask_join_collab_group(record_id)
					if r:
						log_vulnerability(f">>> Found collab feeds of {object_name} could be asked to join.")
					r = unauth_tester.join_collab_group(record_id)
					if r:
						log_vulnerability(f">>> Found collab feeds of {object_name} could be join.")


	# test unauth write
	log_message(f">> Testing unauth write to objects")
	for object_name in available_objects:
		write_allowed  = unauth_tester.attempt_record_create(object_name)
		if write_allowed:
			log_vulnerability(f">>> Found {object_name} to be potentially vulnerable.")
			vulnerability['writable_objects_unauth'].append(object_name)

	if auth_tester:
		# test auth object access
		log_message(f">> Testing auth objects.")
		for object_name in available_objects:
			object_data, record_id = auth_tester.get_object_items(object_name)
			if object_data: # something was returned:
				log_vulnerability(f">>> Found {object_name} to be accessible.")
				object_data_metric = {object_name:{'total_count':object_data['totalCount']}}
				vulnerability['accessible_objects_auth'].append(object_data_metric)
				got_objects.append(object_name)
				log_message(f">> Testing auth update/delete record of object {object_name}")
				r = auth_tester.attempt_record_update(object_name, record_id)
				if r:
					log_vulnerability(f">>> Found record of {object_name} could be updated.")
					vulnerability['update_record_auth'].append(object_name)
				r = auth_tester.attempt_record_delete(record_id)
				if r:
					log_vulnerability(f">>> Found record of {object_name} could be deleted.")
					vulnerability['delete_record_auth'].append(object_name)
				if object_name == "CollaborationGroup" and record_id:
					r = auth_tester.get_collab_feeds(record_id)
					if r:
						log_vulnerability(f">>> Found collab feeds of {object_name} could be extracted.")
					r = auth_tester.ask_join_collab_group(record_id)
					if r:
						log_vulnerability(f">>> Found collab feeds of {object_name} could be asked to join.")
					r = auth_tester.join_collab_group(record_id)
					if r:
						log_vulnerability(f">>> Found collab feeds of {object_name} could be join.")

		# test auth write
		log_message(f">> Testing auth write to objects")
		for object_name in available_objects:
			write_allowed  = auth_tester.attempt_record_create(object_name)
			if write_allowed:
				log_vulnerability(f">>> Found {object_name} to be potentially vulnerable.")
				vulnerability['writable_objects_auth'].append(object_name)
		
		
	flag = True in [len(i) > 0 for i in vulnerability]
	if flag :
		log_vulnerability(f">> Concluding testing for {url}. {url} is vulnerable.")
		final_return = {'vulnerable':True, 'data':vulnerability}
		return final_return
	else:
		log_message(f">> Concluding testing for {url}. {url} is not vulnerable")
		return {'vulnerable':False}

def main():
	today = date.today()
	formatted_date = today.strftime("%m/%d/%Y")
	log_message(f"Scan date: {formatted_date}")
	token = "undefined"
	proxy = False
	output = False
	for i in sys.argv:
		if "proxy=" in i.strip():
			proxy = i.strip().replace("proxy=", "")
		if "token=" in i.strip():
			token = i.strip().replace("token=", "")
		if "output=" in i.strip():
			output = i.strip().replace("output=", "")

	urls = open(sys.argv[1], "r").read().split("\n")
	results = {}
	for url in urls:
		vulnerable_or_not = salesforce_tester(url.strip(), token, proxy)
		results[url] = vulnerable_or_not
	if output:
		with open(output, "w") as file:
			file.write(json.dumps(results, indent=4, separators =(",", ":")))		


main()