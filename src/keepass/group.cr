require "./entry"

module Keepass
  class Group
    property uuid : String
    property name : String
    property parent : Group?
    property children : Array(Group)
    property entries : Array(Entry)

    def initialize(@uuid : String, @name : String, @children : Array(Group), @entries : Array(Entry))
      @children.each { |child| child.parent = self }
    end
  end
end
