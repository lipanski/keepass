module Keepass
  struct Entry
    property uuid : String
    property data : Hash(String, String)
    property created_at : Time?
    property updated_at : Time?
    property last_accessed_at : Time?
    property usage_count : Int32?

    def initialize(@uuid, @data, @created_at, @updated_at, @last_accessed_at, @usage_count)
    end

    def title
      data["title"]
    end

    def url
      data["url"]
    end

    def user_name
      data["user_name"]
    end

    def password
      data["password"]
    end

    def notes
      data["notes"]
    end
  end
end
