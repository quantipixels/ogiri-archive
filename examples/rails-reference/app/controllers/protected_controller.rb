class ProtectedController < ApplicationController
  before_action :authenticate_user!
  def me
    render json: {uid: current_user.uid}
  end
  def admin
    if current_user.role == "admin"
      render json: {uid: current_user.uid}
    else
      head :forbidden
    end
  end
end
