=begin
#Avalara Shipping Verification only

#API for evaluating transactions against direct-to-consumer Beverage Alcohol shipping regulations.  This API is currently in beta. 

SDK Version : 2.4.5.3


=end

require 'spec_helper'

describe AvalaraSdk::Configuration do
  let(:config) { AvalaraSdk::Configuration.default }

  before(:each) do
    # uncomment below to setup host and base_path
    # require 'URI'
    # uri = URI.parse("http://localhost")
    # AvalaraSdk.configure do |c|
    #   c.host = uri.host
    #   c.base_path = uri.path
    # end
  end

  describe '#base_url' do
    it 'should have the default value' do
      # uncomment below to test default value of the base path
      # expect(config.base_url).to eq("http://localhost")
    end

    it 'should remove trailing slashes' do
      [nil, '', '/', '//'].each do |base_path|
        config.base_path = base_path
        # uncomment below to test trailing slashes
        # expect(config.base_url).to eq("http://localhost")
      end
    end
  end
end
