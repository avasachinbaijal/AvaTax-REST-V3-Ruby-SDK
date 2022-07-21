module AvalaraSdk
  class ResponseHash
    attr_accessor :body
    attr_accessor :headers
    attr_accessor :code

    def initialize(body, headers, code)
      @body = body
      @headers = headers
      @code = code
    end
  end
end