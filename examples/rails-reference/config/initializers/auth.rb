def setting_bool(name, default = false)
  ENV.fetch("OGIRI_#{name}", default.to_s) == "true"
end
def setting_int(name, default)
  Integer(ENV.fetch("OGIRI_#{name}", default.to_s))
end
Devise.setup do |config|
  config.mailer_sender = "oracle@example.com"
  config.secret_key = "ogiri-suite-devise-disposable-secret"
  require "devise/orm/active_record"
  config.stretches = 12
  config.paranoid = setting_bool("PARANOID")
  config.maximum_attempts = setting_int("MAXIMUM_ATTEMPTS", 20)
  config.unlock_strategy = ENV.fetch("OGIRI_UNLOCK_STRATEGY", "both").to_sym
  config.unlock_in = setting_int("UNLOCK_IN_SECONDS", 3600).seconds
  config.reset_password_within = setting_int("RESET_PASSWORD_WITHIN_SECONDS", 21600).seconds
  config.reconfirmable = true
end
DeviseTokenAuth.setup do |config|
  config.change_headers_on_each_request = setting_bool("CHANGE_HEADERS_ON_EACH_REQUEST", true)
  config.max_number_of_devices = setting_int("MAX_NUMBER_OF_DEVICES", 10)
  config.token_lifespan = setting_int("TOKEN_LIFESPAN_SECONDS", 1209600).seconds
  config.batch_request_buffer_throttle = setting_int("BATCH_REQUEST_BUFFER_THROTTLE_SECONDS", 5).seconds
  config.redirect_whitelist = ENV.fetch("OGIRI_REDIRECT_ALLOWLIST", "").split(",").reject(&:empty?).presence
  config.default_confirm_success_url = ENV["OGIRI_DEFAULT_CONFIRM_SUCCESS_URL"].presence
  config.default_password_reset_url = ENV["OGIRI_DEFAULT_PASSWORD_RESET_URL"].presence
  config.remove_tokens_after_password_reset = setting_bool("REMOVE_TOKENS_AFTER_PASSWORD_RESET")
  config.require_client_password_reset_token = setting_bool("REQUIRE_CLIENT_PASSWORD_RESET_TOKEN")
  config.check_current_password_before_update = ENV.fetch("OGIRI_CHECK_CURRENT_PASSWORD_BEFORE_UPDATE", "false").then { |v| v == "false" ? false : v.to_sym }
  config.send_confirmation_email = setting_bool("CONFIRMABLE")
  config.cookie_enabled = setting_bool("COOKIE_ENABLED")
  config.cookie_attributes = {secure: false, httponly: true, same_site: :lax}
end
