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
end
