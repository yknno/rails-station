class SessionsController < ApplicationController
  # Bypass CSRF check for callback (OmniAuth handles it or it's standard callback)
  protect_from_forgery except: :create

  def create
    auth = request.env['omniauth.auth']
    
    # Store user details and token info in session
    session[:user_email] = auth.info.email
    session[:user_info] = auth.info
    session[:id_token] = auth.extra.raw_info if auth.extra.present?
    
    redirect_to root_path, notice: "Logged in successfully via OIDC!"
  end

  def destroy
    reset_session
    redirect_to root_path, notice: "Logged out from RP."
  end

  def failure
    redirect_to root_path, alert: "Authentication failed: #{params[:message]}"
  end
end
