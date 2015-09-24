require 'digest/sha2'
require 'rack/utils'
require 'rack/request'
require 'json'
require 'hiredis'
require 'redis'
require 'redis/connection/hiredis'
require 'erubis'

module MyRackup
  class App
    VIEWS_DIR = "#{__dir__}/views"
    LAYOUT_REPLACER = '<%= yield %>'

    def self.users
      @users ||= {}
    end

    def self.view(name)
      @views ||= {}
      @views[name] ||= begin
        path = File.join(VIEWS_DIR, "#{name}.erb")
        Erubis::FastEruby.new(File.read(path)).tap do |erb|
          erb.filename = path
        end
      end
    end

    def self.layout(name)
      @layouts ||= {}
      e = @layouts[name]
      return e if e

      body = layout_(name) { LAYOUT_REPLACER }.split(LAYOUT_REPLACER).each(&:freeze)
      @layouts[name] = body
    end

    def self.layout_(name)
      view(name).result(binding)
    end

    def self.call(env)
      self.new(env).call
    end

    def initialize(env)
      @env = env
      @status = nil
      @headers = {}
      @body = []
    end

    module ResponseMethods
      def response
        [@status || 200, @headers, @body]
      end

      def content_type(type)
        @headers['Content-Type'] = type
      end

      def render(template, layout = :base)
        @headers['Content-Type'] ||= 'text/html'
        @status ||= 200
        @body = erb(template, layout)
      end

      def erb(name, layout = :base)
        if layout
          l = App.layout(layout)
          [l[0], erb(name, nil)[0], l[1]]
        else
          [App.view(name).result(binding)]
        end
      end

      def not_found
        @status = 404
        @headers = {'Content-Type' => 'text/plain'}
        @body = ['not found']
      end

      def redirect(path)
        @status = 302
        @headers['Location'.freeze] = path
      end
    end

    module Helpers
      def request
        @request ||= Rack::Request.new(@env)
      end

      def request_ip
        @env['HTTP_X_FORWARDED_FOR'] || @env['REMOTE_ADDR']
      end

      def cookies
        @cookies ||= @env['HTTP_COOKIE'] ? @env['HTTP_COOKIE'].split(/;\s*/).map{|_| _.split('='.freeze,2) }.to_h : {}
      end

      def cookie_set(key, value)
        (@headers['Set-Cookie'] ||= '') << "#{key}=#{value};path=/\n"
      end

      def cookie_rem(key)
        (@headers['Set-Cookie'] ||= '') << "#{key}=;path=/;max-age=0\n"
      end

      def params
        @params ||= request.params
      end

      def calculate_password_hash(password, salt)
        Digest::SHA256.hexdigest "#{password}:#{salt}"
      end

      def redis
        @redis ||= (Thread.current[:my_redis] ||= Redis.new(path: '/tmp/redis.sock'))
      end

    end

    module Actions
      def action_index
        content_type 'text/html'
        render(:index)
      end

      def action_login
        content_type 'text/html'
        @login = params['login']
        @pass = params['password']
        render(:login)
      end

    end

    include ResponseMethods
    include Helpers
    include Actions

    def call
      meth = @env['REQUEST_METHOD'.freeze]
      path = @env['PATH_INFO'.freeze]

      case
      when path == '/login'.freeze
        action_login
      when meth == 'GET'.freeze
        case path
        when '/'.freeze
          action_index
        else
          not_found
        end
      else
        not_found
      end

      response
    end
  end
end
