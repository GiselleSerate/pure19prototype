import logging



def pause(next_step, last_step=None):
	'''
	Demo helper function to pause execution until you hit enter.
	Takes a description of the next step and (optionally) a description of the
	last step.
	'''
	if last_step:
		logging.info(f"Just finished: {last_step}")
	logging.info(f"Next up: {next_step}")
	input()