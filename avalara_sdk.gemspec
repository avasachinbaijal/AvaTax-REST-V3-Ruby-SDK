# -*- encoding: utf-8 -*-

=begin
#Avalara Shipping Verification only

#API for evaluating transactions against direct-to-consumer Beverage Alcohol shipping regulations.  This API is currently in beta. 

SDK Version : 2.4.5.6


=end

$:.push File.expand_path("../lib", __FILE__)
require "avalara_sdk/version"

Gem::Specification.new do |s|
  s.name        = "avalara_sdk"
  s.version     = AvalaraSdk::VERSION
  s.platform    = Gem::Platform::RUBY
  s.authors     = ["OpenAPI-Generator"]
  s.email       = [""]
  s.homepage    = "https://openapi-generator.tech"
  s.summary     = "Avalara Shipping Verification only Ruby Gem"
  s.description = "API for evaluating transactions against direct-to-consumer Beverage Alcohol shipping regulations.  This API is currently in beta. "
  s.license     = "Unlicense"
  s.required_ruby_version = ">= 2.4"

  s.add_runtime_dependency 'typhoeus', '~> 1.0', '>= 1.0.1'

  s.add_development_dependency 'rspec', '~> 3.6', '>= 3.6.0'

  s.files         = `find *`.split("\n").uniq.sort.select { |f| !f.empty? }
  s.test_files    = `find spec/*`.split("\n")
  s.executables   = []
  s.require_paths = ["lib"]
end
