require_relative './app.rb'

# require 'stackprof' #if ENV['ISUPROFILE']
# Dir.mkdir('/tmp/stackprof') unless File.exist?('/tmp/stackprof')
# use StackProf::Middleware, enabled: ENV['ISUPROFILE'] == ?1, mode: :wall, interval: 500, save_every: 100, path: '/tmp/stackprof'

run MyRackup::App
