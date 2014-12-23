require 'openssl'

module CryptoInterop

  #MS System.Security.Cryptography
  class Rfc2898DeriveBytes
    def initialize(pass, salt)
      @pass = pass
      @salt = salt
      @used = 0
    end

    def get_bytes(qty)
      @used += qty
      entropy = OpenSSL::PKCS5.pbkdf2_hmac_sha1(@pass, @salt, 1000, @used)
      entropy[(@used - qty)..-1]
    end
  end

end
