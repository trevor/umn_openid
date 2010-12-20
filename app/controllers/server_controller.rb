UMNAUTHCOOKIE = 'umnAuthV2'

class ServerController < ApplicationController
  before_filter UMNAuthFilter, :except => [:index, :splash, :login_state, :user_page, :user_xrds, :idp_xrds]

  include ServerHelper
  include OpenID::Server
  
  # custom
  # For https://pip.verisignlabs.com/
  def login_state
    if cookies[ UMNAUTHCOOKIE ] == nil
      session[:umnauth] = nil
    end
    
    if !session[:umnauth]
      # logged out
      t =<<TXT
<?xml version="1.0" encoding="UTF-8" ?> 
<personaConfig version="1.0" serverIdentifier="openid.umn.edu" />
TXT
    else
      # logged in
      t =<<TXT
<?xml version="1.0" encoding="UTF-8" ?> 
<personaConfig version="1.0" serverIdentifier="openid.umn.edu">
  <persona displayName="#{session[:umnauth].internet_id} - umn">https://openid.umn.edu/#{session[:umnauth].internet_id}</persona>
</personaConfig>
TXT
    end
    render :text => t, :layout => false
  end
  
  # custom
  def splash
    if cookies[ UMNAUTHCOOKIE ] == nil
      session[:umnauth] = nil
    end
  end

  # custom
  def login
    redirect_to :action => 'splash'
  end

  # same as example
  def show_decision_page(oidreq, message="Do you wish to authenticate with this site?")
    session[:last_oidreq] = oidreq
    check_oidreq_identity(session[:last_oidreq])
    @oidreq = oidreq

    if message
      flash[:notice] = message
    end

    render :template => 'server/decide', :layout => 'server'
  end
  
  # custom
  def decide
    logger.info '--- here'
    check_oidreq_identity(session[:last_oidreq])
    @oidreq = session[:last_oidreq]
    message="Do you wish to authenticate with this site?"
    
    if message
      flash[:notice] = message
    end
  end
  
  # almost same as example
  def index
    begin
      oidreq = server.decode_request(params)
    rescue ProtocolError => e
      # invalid openid request, so just display a page with an error message
      render :text => "This is an OpenID server endpoint, not a human-readable resource.<br><br>\n\n<pre>\n#{CGI.escapeHTML(e.inspect)}\n</pre>", :status => 500
      return
    end

    # no openid.mode was given
    unless oidreq
      render :text => "This is an OpenID server endpoint."
      return
    end

    oidresp = nil

    if oidreq.kind_of?(CheckIDRequest)

      identity = oidreq.identity

      if oidreq.id_select
        if oidreq.immediate
          oidresp = oidreq.answer(false)
        elsif session[:username].nil?
          # The user hasn't logged in.
          # show_decision_page(oidreq)
          session[:last_oidreq] = oidreq # added
          redirect_to :action => 'decide' # added
          return
        else
          # Else, set the identity to the one the user is using.
          identity = url_for_user
        end
      end

      if oidresp
        nil
      elsif self.is_authorized(identity, oidreq.trust_root)
        oidresp = oidreq.answer(true, nil, identity)

        # add the sreg response if requested
        add_sreg(oidreq, oidresp)
        # ditto pape
        add_pape(oidreq, oidresp)

      elsif oidreq.immediate
        server_url = url_for :action => 'index'
        oidresp = oidreq.answer(false, server_url)

      else
        # show_decision_page(oidreq)
        session[:last_oidreq] = oidreq # added
        redirect_to :action => 'decide' # added
        return
      end

    else
      oidresp = server.handle_request(oidreq)
    end

    self.render_response(oidresp)
  end


  # almost same as example
  def user_page
    # Yadis content-negotiation: we want to return the xrds if asked for.
    accept = request.env['HTTP_ACCEPT']
    
    # This is not technically correct, and should eventually be updated
    # to do real Accept header parsing and logic.  Though I expect it will work
    # 99% of the time.
    if accept and accept.include?('application/xrds+xml')
      user_xrds
      return
    end

    # content negotiation failed, so just render the user page
#    xrds_url = url_for( '/' + params[:username] + '/xrds' ) # this doesn't work with http://rt.cpan.org
    xrds_url = user_page_url(params[:username]) + '/xrds'

    @identity_page_header = <<EOS
<meta http-equiv="X-XRDS-Location" content="#{xrds_url}" />
<link rel="openid.server" href="#{url_for :action => 'index'}" />
<link rel="openid2.provider" href="#{url_for :action => 'index'}" />
EOS

    # Also add the Yadis location header, so that they don't have
    # to parse the html unless absolutely necessary.
    response.headers['X-XRDS-Location'] = xrds_url
  end

  # same as example
  def user_xrds
    types = [
             OpenID::OPENID_2_0_TYPE,
             OpenID::OPENID_1_0_TYPE,
             OpenID::SREG_URI,
            ]

    render_xrds(types)
  end

  # same as example
  def idp_xrds
    types = [
             OpenID::OPENID_IDP_2_0_TYPE,
            ]

    render_xrds(types)
  end

  # almost same as example
  def decision
    oidreq = session[:last_oidreq]
    session[:last_oidreq] = nil

    if params[:yes].nil?
      redirect_to oidreq.cancel_url
      return
    else
      id_to_send = params[:id_to_send]

      # added
      if id_to_send and session[:umnauth].internet_id != id_to_send and id_to_send != ""
        render :text => "id_to_send doesn't match login ID\nid_to_send: #{id_to_send.inspect}\nlogin ID: #{session[:umnauth].internet_id}", :status => 500, :content_type => :text
        return
      end

      identity = oidreq.identity
      if oidreq.id_select
        if id_to_send and id_to_send != ""
          # removed
          # session[:username] = id_to_send
          session[:approvals] = []
          identity = url_for_user
        else
          msg = "You must enter a username to in order to send " +
            "an identifier to the Relying Party."
          show_decision_page(oidreq, msg)
          return
        end
      end

      if session[:approvals]
        session[:approvals] << oidreq.trust_root
      else
        session[:approvals] = [oidreq.trust_root]
      end
      oidresp = oidreq.answer(true, nil, identity)
      add_sreg(oidreq, oidresp)
      add_pape(oidreq, oidresp)
      return self.render_response(oidresp)
    end
  end

  protected

  # new
  def check_oidreq_identity(oidreq)
    if oidreq.identity != url_for_user
      render :text => "openid.identity doesn't match user\nopenid.identity: #{oidreq.identity}\nuser openid known to server as: #{url_for_user}", :status => 500, :content_type => :text
      return
    end
    if oidreq.claimed_id != url_for_user
      render :text => "openid.identity doesn't match user\nopenid.identity: #{oidreq.claimed_id}\nuser openid known to server as: #{url_for_user}", :status => 500, :content_type => :text
      return
    end
  end
  
  # same as example
  def server
    if @server.nil?
      server_url = url_for :action => 'index', :only_path => false
      dir = Pathname.new(RAILS_ROOT).join('db').join('openid-store')
      store = OpenID::Store::Filesystem.new(dir)
      @server = Server.new(store, server_url)
    end
    return @server
  end

  # same as example
  def approved(trust_root)
    return false if session[:approvals].nil?
    return session[:approvals].member?(trust_root)
  end

  # custom
  def username_from_identity_url(identity_url)
    identity_url.gsub(request.url, '')
  end
  
  # custom
  def is_authorized(identity_url, trust_root)
    return  ( cookies[ UMNAUTHCOOKIE ] and session[:umnauth] and 
              ( username_from_identity_url( identity_url ) == session[:umnauth].internet_id ) and 
              self.approved( trust_root ) )
  end

  # modified from example
  def render_xrds(types)
    type_str = types.map{|uri| "<Type>#{uri}</Type>"}.join("\n      ")

    yadis = <<EOS
<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS
    xmlns:xrds="xri://$xrds"
    xmlns:openid="http://openid.net/xmlns/1.0"
    xmlns="xri://$xrd*($v*2.0)">
  <XRD>
    <Service priority="0">
      #{type_str}
      <URI>#{url_for(:controller => 'server', :only_path => false)}</URI>
      <LocalID>#{user_page_url(params[:username])}</LocalID>
    </Service>
    
    <Service priority="1">
      <Type>http://openid.net/signon/1.1</Type>
      <Type>http://openid.net/sreg/1.0</Type>
      <Type>http://openid.net/extensions/sreg/1.1</Type>
      <URI>#{url_for(:controller => 'server', :only_path => false)}</URI>
      <openid:Delegate>#{user_page_url(params[:username])}</openid:Delegate>
    </Service>
  </XRD>
</xrds:XRDS>
EOS

    render :text => yadis, :content_type => Mime::XRDS
  end  

  # same as example
  # TODO needs work if people actually want this feature
  def add_sreg(oidreq, oidresp)
    # check for Simple Registration arguments and respond
    sregreq = OpenID::SReg::Request.from_openid_request(oidreq)

    return if sregreq.nil?
    # In a real application, this data would be user-specific,
    # and the user should be asked for permission to release
    # it.
    sreg_data = {
      'nickname' => session[:umnauth].internet_id,
      'fullname' => session[:umnauth].internet_id,
      'email' => "#{session[:umnauth].internet_id}@umn.edu"
    }

    sregresp = OpenID::SReg::Response.extract_response(sregreq, sreg_data)
    oidresp.add_extension(sregresp)
  end

  # same as example
  def add_pape(oidreq, oidresp)
    papereq = OpenID::PAPE::Request.from_openid_request(oidreq)
    return if papereq.nil?
    paperesp = OpenID::PAPE::Response.new
    paperesp.nist_auth_level = 0 # we don't even do auth at all!
    oidresp.add_extension(paperesp)
  end

  # same as example
  def render_response(oidresp)
    if oidresp.needs_signing
      signed_response = server.signatory.sign(oidresp)
    end
    web_response = server.encode_response(oidresp)

    case web_response.code
    when HTTP_OK
      render :text => web_response.body, :status => 200

    when HTTP_REDIRECT
      redirect_to web_response.headers['location']

    else
      render :text => web_response.body, :status => 400
    end
  end

end
