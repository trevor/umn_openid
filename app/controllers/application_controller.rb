class ApplicationController < ActionController::Base
#  before_filter :log_request

  def log_request
    logger.info request.inspect
  end
  
end
