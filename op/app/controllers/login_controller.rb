class LoginController < ApplicationController
  # We don't want to authenticate_user! globally here, we handle it custom
  skip_before_action :authenticate_user!, raise: false

  def new
    handler = LoginFlowHandler.new(
      challenge: params[:login_challenge],
      current_user: current_user,
      session: session
    )
    result = handler.handle_new

    if result.success?
      if result.action == :redirect_to_hydra
        redirect_to result.redirect_to, allow_other_host: true
      elsif result.action == :redirect_to_new_session
        sign_out(current_user) if result.force_sign_out && user_signed_in?
        redirect_to new_user_session_path
      end
    else
      redirect_to root_path, alert: result.error_message
    end
  end

  def reject
    challenge = params[:login_challenge] || session.delete(:login_challenge)
    handler = LoginFlowHandler.new(
      challenge: challenge,
      current_user: current_user,
      session: session
    )
    result = handler.handle_reject

    if result.success?
      redirect_to result.redirect_to, allow_other_host: true
    else
      redirect_to root_path, alert: result.error_message
    end
  end
end
