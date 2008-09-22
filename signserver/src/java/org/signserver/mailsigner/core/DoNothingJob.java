package org.signserver.mailsigner.core;

import org.quartz.Job;
import org.quartz.JobExecutionContext;
import org.quartz.JobExecutionException;

/**
 * This job does nothing, it's the trigger listener that
 * does the wrapping between quartz job and timed service. 
 * 
 * @author Philip Vendil 18 sep 2008
 *
 * @version $Id$
 */

public class DoNothingJob implements Job{

	public DoNothingJob(){}
	
	@Override
	public void execute(JobExecutionContext arg0)
			throws JobExecutionException {
		// Do Nothing			
	}
	
}
