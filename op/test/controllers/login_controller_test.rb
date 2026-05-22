require "test_helper"

class LoginControllerTest < ActionDispatch::IntegrationTest
  include Devise::Test::IntegrationHelpers

  setup do
    @user = users(:one)
  end

  test "should redirect to root with alert on missing login challenge" do
    get "/login"
    assert_redirected_to root_path
    assert_equal "Missing login challenge.", flash[:alert]
  end

  test "should redirect to devise sign in when login challenge is present and user not authenticated" do
    mock_service = Minitest::Mock.new
    mock_service.expect :get_login_request, { "skip" => false }, ["test-challenge"]

    OryHydraService.stub :new, mock_service do
      get "/login", params: { login_challenge: "test-challenge" }
      assert_redirected_to new_user_session_path
      assert_equal "test-challenge", session[:login_challenge]
    end
    mock_service.verify
  end

  test "should auto-accept login request when user is already signed in" do
    sign_in @user

    mock_service = Minitest::Mock.new
    mock_service.expect :get_login_request, { "skip" => false }, ["test-challenge"]
    mock_service.expect :accept_login_request, { "redirect_to" => "http://hydra/redirect" }, ["test-challenge", @user.id.to_s]

    OryHydraService.stub :new, mock_service do
      get "/login", params: { login_challenge: "test-challenge" }
      assert_redirected_to "http://hydra/redirect"
    end
    mock_service.verify
  end

  test "should rescue OryHydraService::Error and redirect to root with alert" do
    mock_service = Minitest::Mock.new
    mock_service.expect :get_login_request, nil do
      raise OryHydraService::Error, "mock error description"
    end

    OryHydraService.stub :new, mock_service do
      get "/login", params: { login_challenge: "test-challenge" }
      assert_redirected_to root_path
      assert_equal "Error communicating with Hydra: mock error description", flash[:alert]
    end
  end

  test "should force re-authentication when user is signed in but prompt=login is requested" do
    sign_in @user

    mock_service = Minitest::Mock.new
    mock_service.expect :get_login_request, { "skip" => false, "request_url" => "http://hydra/auth?prompt=login" }, ["test-challenge"]

    OryHydraService.stub :new, mock_service do
      get "/login", params: { login_challenge: "test-challenge" }
      assert_redirected_to new_user_session_path
      assert_not controller.user_signed_in?
    end
    mock_service.verify
  end

  test "should not force re-authentication when prompt=login is requested but user authenticated after challenge start" do
    mock_service = Minitest::Mock.new
    mock_service.expect :get_login_request, { "skip" => false, "request_url" => "http://hydra/auth?prompt=login" }, ["test-challenge"]
    mock_service.expect :get_login_request, { "skip" => false, "request_url" => "http://hydra/auth?prompt=login" }, ["test-challenge"]
    mock_service.expect :accept_login_request, { "redirect_to" => "http://hydra/redirect" }, ["test-challenge", @user.id.to_s]

    OryHydraService.stub :new, mock_service do
      # 1. First request, redirects to Devise login page and sets session[:prompt_login_triggered_for]
      get "/login", params: { login_challenge: "test-challenge" }
      assert_redirected_to new_user_session_path

      # 2. Login via Devise
      post "/users/sign_in", params: { user: { email: @user.email, password: "password123" } }
      assert_redirected_to "/login?login_challenge=test-challenge"

      # 3. Follow the redirect, should not force sign out again, should accept login
      follow_redirect!
      assert_redirected_to "http://hydra/redirect"
    end
    mock_service.verify
  end
end
