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

  class PasswordDeriveBytes
    def initialize(pass, salt, algo, iter)
      @pass = pass
      @salt = salt
      @iter = iter
      @hash = OpenSSL::Digest.new(algo)
    end

    def get_bytes(qty)
      raise 'only size %s supported' % @hash.length if qty != @hash.length
      dgst = @hash.update(@pass + @salt).digest

      (@iter-1).times.reduce(dgst) do |dgst|
        @hash.reset.update(dgst).digest
      end
    end
  end

  class Rijndael
    def initialize(key, iv = nil)
      @key = key
      @iv  = iv
    end

    def self.new_with_pbkdf(pbkdf)
      key = pbkdf.get_bytes(256/8)
      iv  = pbkdf.get_bytes(128/8)
      new(key, iv)
    end

    def decrypt(cipher_text)
      crypt(cipher_text, get_aes.decrypt)
    end

    def encrypt(plain_text)
      crypt(plain_text, get_aes.encrypt)
    end

    private

    def get_aes
      @aes ||= OpenSSL::Cipher.new('AES-256-CBC')
    end

    def crypt(text, aes)
      aes.key = @key
      aes.iv  = @iv
      aes.update(text) + aes.final
    end
  end

end
