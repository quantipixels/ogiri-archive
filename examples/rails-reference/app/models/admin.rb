class Admin < ApplicationRecord
  modules = %i[database_authenticatable registerable recoverable validatable]
  modules << :confirmable if setting_bool("CONFIRMABLE")
  modules << :lockable if setting_bool("LOCKABLE")
  devise(*modules)
  include DeviseTokenAuth::Concerns::User
end
