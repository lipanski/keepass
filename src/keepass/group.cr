require "./entry"

module Keepass
  class Group
    property uuid : String
    property name : String
    property parent : Group?
    property groups : Array(Group)
    property entries : Array(Entry)

    def initialize(@uuid : String, @name : String, @groups : Array(Group), @entries : Array(Entry))
      @groups.each { |group| group.parent = self }
    end

    def all_entries : Array(Entry)
      entries + groups.reduce(Array(Entry).new) { |acc, group| acc += group.all_entries }
    end
  end
end
