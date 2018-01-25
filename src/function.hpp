/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2013-2017 Regents of the University of California.
 *
 * This file is part of ndn-cxx library (NDN C++ library with eXperimental eXtensions).
 *
 * ndn-cxx library is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * ndn-cxx library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received copies of the GNU General Public License and GNU Lesser
 * General Public License along with ndn-cxx, e.g., in COPYING.md file.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndn-cxx authors and contributors.
 *
 * @author Jeff Thompson <jefft0@remap.ucla.edu>
 * @author Alexander Afanasyev <http://lasr.cs.ucla.edu/afanasyev/index.html>
 * @author Zhenkai Zhu <http://irl.cs.ucla.edu/~zhenkai/>
 */

#ifndef NDN_FUNCTION_HPP
#define NDN_FUNCTION_HPP

#include "name-component.hpp"
#include <iterator>

namespace ndn {

class Function;


using PartialFunction = Function;


class Function
{
public: // nested types
  class Error : public name::Component::Error
  {
  public:
    explicit
    Error(const std::string& what)
      : name::Component::Error(what)
    {
    }
  };

  using Component = name::Component;
  using component_container = std::vector<Component>;

  // Function appears as a container of name components
  using value_type             = Component;
  using allocator_type         = void;
  using reference              = Component&;
  using const_reference        = const Component&;
  using pointer                = Component*;
  using const_pointer          = const Component*;
  using iterator               = const Component*; // disallow modifying via iterator
  using const_iterator         = const Component*;
  using reverse_iterator       = std::reverse_iterator<iterator>;
  using const_reverse_iterator = std::reverse_iterator<const_iterator>;
  using difference_type        = component_container::difference_type;
  using size_type              = component_container::size_type;

public: // constructors, encoding, decoding

  Function();


  explicit
  Function(const Block& wire);


  Function(const char* uri);


  Function(std::string uri);


  std::string
  toUri() const;


  bool
  hasWire() const
  {
    return m_wire.hasWire();
  }


  template<encoding::Tag TAG>
  size_t
  wireEncode(EncodingImpl<TAG>& encoder) const;


  const Block&
  wireEncode() const;

  void
  wireDecode(const Block& wire);

  Function
  deepCopy() const;

public: // access

  bool
  empty() const
  {
    return m_wire.elements().empty();
  }

  size_t
  size() const
  {
    return m_wire.elements_size();
  }

  const Component&
  get(ssize_t i) const
  {
    if (i < 0) {
      i += size();
    }
    return reinterpret_cast<const Component&>(m_wire.elements()[i]);
  }

  const Component&
  operator[](ssize_t i) const
  {
    return get(i);
  }

  const Component&
  at(ssize_t i) const;

  PartialFunction
  getSubFunction(ssize_t iStartComponent, size_t nComponents = npos) const;

  PartialFunction
  getPrefix(ssize_t nComponents) const
  {
    if (nComponents < 0)
      return getSubFunction(0, size() + nComponents);
    else
      return getSubFunction(0, nComponents);
  }

public: // iterators

  const_iterator
  begin() const
  {
    return reinterpret_cast<const_iterator>(m_wire.elements().data());
  }


  const_iterator
  end() const
  {
    return reinterpret_cast<const_iterator>(m_wire.elements().data() + m_wire.elements().size());
  }

  const_reverse_iterator
  rbegin() const
  {
    return const_reverse_iterator(end());
  }

  const_reverse_iterator
  rend() const
  {
    return const_reverse_iterator(begin());
  }

public: // modifiers
  Function&
  append(const Component& component)
  {
    m_wire.push_back(component);
    return *this;
  }

  Function&
  append(const char* value)
  {
    return append(Component(value));
  }

  Function&
  append(const uint8_t* value, size_t valueLength)
  {
    return append(Component(value, valueLength));
  }

  template<class Iterator>
  Function&
  append(Iterator first, Iterator last)
  {
    static_assert(sizeof(typename std::iterator_traits<Iterator>::value_type) == 1,
                  "iterator does not dereference to one-octet value type");
    return append(Component(first, last));
  }

  Function&
  append(const Block& value)
  {
    if (value.type() == tlv::NameComponent) {
      m_wire.push_back(value);
    }
    else {
      m_wire.push_back(Block(tlv::NameComponent, value));
    }

    return *this;
  }

  Function&
  appendNumber(uint64_t number)
  {
    return append(Component::fromNumber(number));
  }

  Function&
  appendNumberWithMarker(uint8_t marker, uint64_t number)
  {
    return append(Component::fromNumberWithMarker(marker, number));
  }

  Function&
  appendVersion(uint64_t version)
  {
    return append(Component::fromVersion(version));
  }

  Function&
  appendVersion();

  Function&
  appendSegment(uint64_t segmentNo)
  {
    return append(Component::fromSegment(segmentNo));
  }

  Function&
  appendSegmentOffset(uint64_t offset)
  {
    return append(Component::fromSegmentOffset(offset));
  }

  Function&
  appendTimestamp(const time::system_clock::TimePoint& timePoint)
  {
    return append(Component::fromTimestamp(timePoint));
  }

  Function&
  appendTimestamp();

  Function&
  appendSequenceNumber(uint64_t seqNo)
  {
    return append(Component::fromSequenceNumber(seqNo));
  }

  Function&
  appendImplicitSha256Digest(const ConstBufferPtr& digest)
  {
    return append(Component::fromImplicitSha256Digest(digest));
  }

  Function&
  appendImplicitSha256Digest(const uint8_t* digest, size_t digestSize)
  {
    return append(Component::fromImplicitSha256Digest(digest, digestSize));
  }

  Function&
  append(const PartialFunction& name);

  template<class T>
  void
  push_back(const T& component)
  {
    append(component);
  }

  void
  clear()
  {
    m_wire = Block(tlv::FunctionName);
  }

public: // algorithms
  Function
  getSuccessor() const;

  bool
  isPrefixOf(const Function& other) const;

  bool
  equals(const Function& other) const;

  int
  compare(const Function& other) const
  {
    return this->compare(0, npos, other);
  }

  int
  compare(size_t pos1, size_t count1,
          const Function& other, size_t pos2 = 0, size_t count2 = npos) const;

public:
  static const size_t npos;

private:
  mutable Block m_wire;
};

NDN_CXX_DECLARE_WIRE_ENCODE_INSTANTIATIONS(Function);

inline bool
operator==(const Function& lhs, const Function& rhs)
{
  return lhs.equals(rhs);
}

inline bool
operator!=(const Function& lhs, const Function& rhs)
{
  return !lhs.equals(rhs);
}

inline bool
operator<=(const Function& lhs, const Function& rhs)
{
  return lhs.compare(rhs) <= 0;
}

inline bool
operator<(const Function& lhs, const Function& rhs)
{
  return lhs.compare(rhs) < 0;
}

inline bool
operator>=(const Function& lhs, const Function& rhs)
{
  return lhs.compare(rhs) >= 0;
}

inline bool
operator>(const Function& lhs, const Function& rhs)
{
  return lhs.compare(rhs) > 0;
}

std::ostream&
operator<<(std::ostream& os, const Function& name);

std::istream&
operator>>(std::istream& is, Function& name);

} // namespace ndn

namespace std {

template<>
struct hash<ndn::Function>
{
  size_t
  operator()(const ndn::Function& name) const;
};

} // namespace std

#endif // NDN_NAME_HPP
