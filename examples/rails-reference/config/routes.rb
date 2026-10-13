Rails.application.routes.draw do
  mount_devise_token_auth_for "User", at: "auth"
  mount_devise_token_auth_for "Admin", at: "admin_auth"
  get "/me", to: "protected#me"
  get "/admin", to: "protected#admin"
  get "/health", to: proc { [200, {"content-type" => "text/plain"}, ["ok"]] }
end
