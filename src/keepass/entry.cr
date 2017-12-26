module Keepass
  struct Entry
    property uuid : String
    property title : String?
    property url : String?
    property user : String?
    property password : String?
    property notes : String?
    property created_at : Time?
    property updated_at : Time?
    property last_accessed_at : Time?
    property usage_count : Int32?

    def initialize(@uuid, @title, @url, @user, @password, @notes, @created_at, @updated_at, @last_accessed_at, @usage_count)
    end
  end
end
