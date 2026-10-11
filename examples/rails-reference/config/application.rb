require_relative "boot"
require "rails"
require "active_record/railtie"
require "action_controller/railtie"
require "action_mailer/railtie"
Bundler.require(*Rails.groups)
module Oracle
  class Application < Rails::Application
    config.load_defaults 8.0
    config.api_only = true
    config.eager_load = false
    config.secret_key_base = "ogiri-suite-disposable-oracle-secret-" * 4
    config.hosts.clear
    config.action_dispatch.show_exceptions = :all
    config.consider_all_requests_local = false
    config.middleware.use ActionDispatch::Cookies
    config.session_store :cookie_store, key: "_oracle_session"
    config.middleware.use ActionDispatch::Session::CookieStore, config.session_options
    config.action_controller.raise_on_open_redirects = false
    config.middleware.insert_before 0, Rack::Cors do
      allow do
        origins "*"
        resource "*", headers: :any, methods: :any,
          expose: %w[access-token client uid expiry token-type Authorization]
      end
    end
    config.action_mailer.delivery_method = :smtp
    config.action_mailer.smtp_settings = {
      address: ENV.fetch("OGIRI_SMTP_HOST", "localhost"),
      port: ENV.fetch("OGIRI_SMTP_PORT", "1025").to_i
    }
    config.action_mailer.default_url_options = {host: "localhost", port: ENV.fetch("PORT", "3000").to_i}
    config.action_mailer.raise_delivery_errors = true
    config.filter_parameters += %i[password password_confirmation current_password access-token tokens reset_password_token confirmation_token unlock_token]
    config.logger = Logger.new($stdout)
    config.log_level = :warn
  end
end
