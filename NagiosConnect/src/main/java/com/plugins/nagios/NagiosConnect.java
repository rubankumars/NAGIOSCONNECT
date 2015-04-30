package com.plugins.nagios;
import hudson.Launcher;
import hudson.Extension;
import hudson.util.FormValidation;
import hudson.model.AbstractBuild;
import hudson.model.BuildListener;
import hudson.model.AbstractProject;
import hudson.tasks.Builder;
import hudson.tasks.BuildStepDescriptor;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.QueryParameter;

import javax.servlet.ServletException;
import java.io.IOException;
import java.text.ParseException;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.PasswordAuthentication;
import java.net.URL;
import java.util.Date;
import java.util.Calendar;
import java.text.SimpleDateFormat;

/**
 *
 * @author Rubankumar
 * @email ruban.yuvaraj@gmail.com
 *
 */

public class NagiosConnect extends Builder {

    private final String servername;
    private final String jobname;
    int minutes = 0;
    private final String nagiosStatus;

    // Fields in config.jelly must match the parameter names in the "DataBoundConstructor"
    @DataBoundConstructor
    public NagiosConnect(String servername, String jobname, int minutes, String nagiosStatus) {
        this.servername = servername;
	this.jobname = jobname;
	this.minutes = minutes;
	this.nagiosStatus = nagiosStatus;
    }

    /**
     * We'll use this from the <tt>config.jelly</tt>.
     */
    public String getServername() {
        return servername;
    }
    public String getJobname() {
        return jobname;
    }
    public int getMinutes() {
        return minutes;
    }
    public String getNagiosStatus(){
	return nagiosStatus;
    }
    
	public static String excutePost(String NAGIOSURL, String URLPARAMETER, String user, String password) {
		  HttpURLConnection connection = null; 
			final String username = user;
			final String pass = password;
		  try {
		    //Create connection
		    URL url = new URL(NAGIOSURL);
		    Authenticator.setDefault (new Authenticator() {
		        protected PasswordAuthentication getPasswordAuthentication() {
		            return new PasswordAuthentication (username, pass.toCharArray());
		        }
		    });
		    connection = (HttpURLConnection)url.openConnection();
		    connection.setRequestMethod("POST");
		    connection.setRequestProperty("Content-Type", 
		        "application/x-www-form-urlencoded");

		    connection.setRequestProperty("Content-Length",Integer.toString(URLPARAMETER.getBytes().length));
		    connection.setRequestProperty("Content-Language", "en-US");  

		    connection.setUseCaches(false);
		    connection.setDoOutput(true);

		    //Send request
		    DataOutputStream wr = new DataOutputStream (
		        connection.getOutputStream());
		    wr.writeBytes(URLPARAMETER);
		    wr.close();

		    //Get Response  
		    InputStream is = connection.getInputStream();
		    BufferedReader rd = new BufferedReader(new InputStreamReader(is));
		    StringBuilder response = new StringBuilder(); // or StringBuffer if not Java 5+ 
		    String line;
		    while((line = rd.readLine()) != null) {
		      response.append(line);
		      response.append('\r');
		    }
		    rd.close();
		    return response.toString();
		  } catch (Exception e) {
		    e.printStackTrace();
		    return null;
		  } finally {
		    if(connection != null) {
		      connection.disconnect(); 
		    }
		  }
		}

    @Override
    public boolean perform(AbstractBuild build, Launcher launcher, BuildListener listener) {
        // This is where you 'build' the project.
        // Since this is a dummy, we just say 'hello world' and call that a build.

        // This also shows how you can consult the global configuration of the builder
        //if (getDescriptor().getUseFrench())
          ///  listener.getLogger().println("Bonjour, "+name+"!");
        ///else
	    listener.getLogger().println(getDescriptor().getNagiosUrl());
	    listener.getLogger().println(getDescriptor().getNagiosUser());
	    listener.getLogger().println(getDescriptor().getNagiosPassword());
            listener.getLogger().println("ServerName you have entered is " + servername);
            listener.getLogger().println("JobName you have entered is " + jobname);
            listener.getLogger().println("Minutes you have entered is " + minutes);
            listener.getLogger().println("Service entered is " + nagiosStatus);

            final String url = getDescriptor().getNagiosUrl();
            final String user = getDescriptor().getNagiosUser();
            final String password = getDescriptor().getNagiosPassword();
	    final String NAGIOSURL = url + "/cgi-bin/cmd.cgi";

	    String pattern =  "MM-dd-yyy HH:mm:ss";
	    SimpleDateFormat format = new SimpleDateFormat(pattern);
	    Date now = new Date();
	    String startDate = format.format(now);
		Date advanceTime = null;
		try{
		advanceTime = format.parse(startDate);
		}catch (ParseException e) {
		e.printStackTrace();
		} 
	    Calendar cal = Calendar.getInstance();
	    cal.setTime(advanceTime);
	    cal.add(Calendar.MINUTE, minutes);
	    String endDate =  format.format(cal.getTime());

            listener.getLogger().println("StartDate " + startDate);
            listener.getLogger().println("EndDate " + endDate);

	if(nagiosStatus.equals("nagiosPause")){
	    
//	        final String NAGIOSURL = url + "/cgi-bin/cmd.cgi";
                String URLPARAMETER = "cmd_typ=56&cmd_mod=2&host="+servername+"&service="+jobname+"&com_data=Build and Deploy is in progress&trigger=0&start_time="+startDate+"&end_time="+endDate+"&fixed=1&hours=2&minutes=0&btnSubmit=Commit";
                listener.getLogger().println(excutePost(NAGIOSURL,URLPARAMETER,user,password));

	}
	else if (nagiosStatus.equals("nagiosStart")){
			final String NAGIOSURL_DOWNID = url + "/cgi-bin/extinfo.cgi";
			String URLPARAMETER = "type=6";
			String output=excutePost(NAGIOSURL_DOWNID,URLPARAMETER,user,password);
			for(int index = output.indexOf("down_id");index>=0; index = output.indexOf("down_id", index+1))
			{
				String a = output.substring(index-500, index+15);
				if ( (a.indexOf(servername)>-1) && (a.indexOf(jobname)>-1) ){
				String b = output.substring(index, index+20);
				String downtime_ID =  (b.substring(8, b.indexOf("'><"))).trim();
				listener.getLogger().println(downtime_ID);
				String URLPARAMETER_DEL = "cmd_mod=2&cmd_typ=79&down_id="+downtime_ID+"btnSubmit=Commit";
				listener.getLogger().println(excutePost(NAGIOSURL,URLPARAMETER_DEL,user,password));		
				}
			}
	}
	return true;
    }

    // Overridden for better type safety.
    // If your plugin doesn't really define any property on Descriptor,
    // you don't have to do this.
    @Override
    public DescriptorImpl getDescriptor() {
        return (DescriptorImpl)super.getDescriptor();
    }

    /**
     * Descriptor for {@link HelloWorldBuilder}. Used as a singleton.
     * The class is marked as public so that it can be accessed from views.
     *
     * <p>
     * See <tt>src/main/resources/hudson/plugins/hello_world/HelloWorldBuilder/*.jelly</tt>
     * for the actual HTML fragment for the configuration screen.
     */
    @Extension // This indicates to Jenkins that this is an implementation of an extension point.
    public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {
        /**
         * To persist global configuration information,
         * simply store it in a field and call save().
         *
         * <p>
         * If you don't want fields to be persisted, use <tt>transient</tt>.
         */
        private String nagiosUrl;
        private String nagiosUser;
        private String nagiosPassword;


        /**
         * Performs on-the-fly validation of the form field 'name'.
         *
         * @param value
         *      This parameter receives the value that the user has typed.
         * @return
         *      Indicates the outcome of the validation. This is sent to the browser.
         */
        public FormValidation doCheckName(@QueryParameter String value)
                throws IOException, ServletException {
            if (value.length() == 0)
                return FormValidation.error("Please set a name");
            if (value.length() < 4)
                return FormValidation.warning("Isn't the name too short?");
            return FormValidation.ok();
        }

        public boolean isApplicable(Class<? extends AbstractProject> aClass) {
            // Indicates that this builder can be used with all kinds of project types 
            return true;
        }

        /**
         * This human readable name is used in the configuration screen.
         */
        public String getDisplayName() {
            return "Nagios Configuration";
        }

        @Override
        public boolean configure(StaplerRequest req, JSONObject formData) throws FormException {
            // To persist global configuration information,
            // set that to properties and call save().
            nagiosUrl = formData.getString("nagiosUrl");
	    nagiosUser = formData.getString("nagiosUser");
	    nagiosPassword = formData.getString("nagiosPassword");
            // ^Can also use req.bindJSON(this, formData);
            //  (easier when there are many fields; need set* methods for this, like setUseFrench)
            save();
            return super.configure(req,formData);
        }

        /**
         * This method returns true if the global configuration says we should speak French.
         *
         * The method name is bit awkward because global.jelly calls this method to determine
         * the initial state of the checkbox by the naming convention.
         */
       public String getNagiosUrl() {
         return nagiosUrl;
       }

       public String getNagiosUser() {
         return nagiosUser;
       }

       public String getNagiosPassword() {
         return nagiosPassword;
       }

    }
}

