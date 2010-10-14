require File.expand_path('../boot', __FILE__)

# Pick the frameworks you want:
# require "active_record/railtie"
require "action_controller/railtie"
require "action_mailer/railtie"
#require "active_resource/railtie"
#require "rails/test_unit/railtie"

# If you have a Gemfile, require the gems listed there, including any gems
# you've limited to :test, :development, or :production.
Bundler.require(:default, Rails.env) if defined?(Bundler)

module UMNOpenID
  class Application < Rails::Application
#    Rails.env = 'development'
    require 'pathname'
    require 'openid/consumer/discovery'
    require 'openid/extensions/sreg'
    require 'openid/extensions/pape'
    require 'openid/store/filesystem'
    config.time_zone = 'Central Time (US & Canada)'
    config.encoding = "utf-8"
  end
end
