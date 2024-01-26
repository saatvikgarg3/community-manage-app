const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const {collection,Communitycollection,Rolecollection,Membercollection} = require('./config');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

const SECRET_KEY = 'your_secret_key'; // Replace with a secure secret key
function generateSlug(name) {
    return name.toLowerCase().replace(/\s+/g, '-');
}
const authenticateToken = (req, res, next) => {
    const accessToken = req.headers['authorization'];

    if (!accessToken) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    jwt.verify(accessToken, SECRET_KEY, async (err, decoded) => {
        if (err) {
            return res.status(403).json({ error: 'Token verification failed' });
        }

        const user = await collection.findById(decoded.userId).select('-password');

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        req.user = user; // Attached user details to req
        next();
    });
};

//Authentication Endpoints
app.post('/v1/auth/signup', async (req, res) => {
    try {
        const data = {
            name: req.body.name,
            email: req.body.email,
            password: req.body.password,
            created_at: new Date(), // Add created_at field
        };

        // Checking if user already exists
        const existingUser = await collection.findOne({ email: data.email });
        if (existingUser) {
            return res.status(400).json({ error: 'User already exists. Please choose a different name.' });
        }

        // Hashing the password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(data.password, saltRounds);
        data.password = hashedPassword;

        // Inserting the new user into the usercollection
        const result = await collection.insertMany(data);

        // Generating an access token (example using jsonwebtoken)
        const accessToken = jwt.sign({ userId: result.insertedId }, SECRET_KEY);

        // Sending a success response with the specified structure
        res.status(201).json({
            status: true,
            content: {
                data: {
                    id: result.insertedId,
                    name: data.name,
                    email: data.email,
                    created_at: data.created_at,
                },
                meta: {
                    access_token: accessToken,
                },
            },
        });

        console.log('Signup Successfully Completed', result);
    } catch (error) {
        // Handling errors
        console.error('Error during signup:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post("/v1/auth/signin",async(req,res)=>{
    try {
        const user = await collection.findOne({ email: req.body.email });

        if (!user) {
            return res.status(401).json({ error: 'User not found' });
        }

        const isPasswordMatch = await bcrypt.compare(req.body.password, user.password);

        if (!isPasswordMatch) {
            return res.status(401).json({ error: 'Invalid password' });
        }

        // Generate an access token
        const accessToken = jwt.sign(
            {
                userId: user._id,
                name: user.name,
                email: user.email,
            },
            SECRET_KEY,
            { expiresIn: '1h' } // Token expiration time, adjust as needed
        );

        // Return the response in the specified format
        res.status(200).json({
            status: true,
            content: {
                data: {
                    id: user._id,
                    name: user.name,
                    email: user.email,
                    created_at: user.created_at,
                },
                meta: {
                    access_token: accessToken,
                },
            },
        });
    } catch (error) {
        console.error('Error during sign-in:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
})

app.get('/v1/auth/me', authenticateToken, (req, res) => {
    // The user details are now available in req.user
    res.status(200).json({
        status: true,
        content: {
            data: {
                id: req.user._id,
                name: req.user.name,
                email: req.user.email,
                created_at: req.user.created_at,
            },
        },
    });
});

//Role endpoints
app.post('/v1/role',authenticateToken,async (req, res) => {
  try {
    // authentication middleware above added user information to req.user
    const userId = req.user._id;

    // Checking if the user is allowed to create a role (you can define your own logic)
    // For example, Here it allows any authenticated user to create a role.

    // Extracting role name from the request body
    const { name } = req.body;

    // Creating a new role
    const newRole = new Rolecollection({
      name: name,
    });

    // Save the role to the database
    await newRole.save();

    const response = {
      status: true,
      content: {
        data: {
          id: newRole._id, 
          name: newRole.name,
          created_at: newRole.createdAt,
          updated_at: newRole.updatedAt,
        },
      },
    };

    return res.status(201).json(response);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Endpoint to get all roles with pagination
app.get('/v1/role', authenticateToken, async (req, res) => {
  try {
    //authentication middleware adds user information to req.user
    const userId = req.user._id;

    // Pagination parameters (can be adjusted as needed)
    const page = parseInt(req.query.page) || 1;
    const pageSize = 10;

    // Fetching total count of roles
    const totalRolesCount = await Rolecollection.countDocuments({ userid: userId });

    if (totalRolesCount === 0) {
      return res.status(200).json({
        status: true,
        content: {
          meta: {
            total: 0,
            pages: 0,
            page: page,
          },
          data: [],
        },
      });
    }

    // Calculating total number of pages
    const totalPages = Math.ceil(totalRolesCount / pageSize);

    // Checking if the requested page is valid
    if (page > totalPages || page < 1) {
      return res.status(400).json({ error: 'Invalid page number' });
    }

    // Fetching roles with pagination
    const roles = await Rolecollection.find()
      .skip((page - 1) * pageSize)
      .limit(pageSize);

    const response = {
      status: true,
      content: {
        meta: {
          total: totalRolesCount,
          pages: totalPages,
          page: page,
        },
        data: roles.map(role => ({
          id: role._id,
          name: role.name,
          created_at: role.createdAt,
          updated_at: role.updatedAt,
        })),
      },
    };

    return res.status(200).json(response);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});



//Community endpoints

//endpoint to create community
app.post('/v1/community', authenticateToken, async (req, res) => {
    try {
      const { name } = req.body;
      const slug = generateSlug(name);
      const owner = req.user._id;
  

      // Checking if the community with the same name already exists
        const existingCommunity = await Communitycollection.findOne({ name });
        if (existingCommunity) {
            return res.status(400).json({ error: 'Community with the same name already exists.' });
        }


      // Created the community
      const community = await Communitycollection.create({
        name,
        slug,
        owner,
        createdAt: new Date(),
        updatedAt: null,
      });
  
      // Check if the 'Community Admin' role already exists
    let communityAdminRole = await Rolecollection.findOne({ name: 'Community Admin' });

    // If 'Community Admin' role doesn't exist, create it
    if (!communityAdminRole) {
      communityAdminRole = await Rolecollection.create({
        name: 'Community Admin',
      });
    }

      const communityAdminMember = await Membercollection.create({
        communityid:community._id,
        userid: owner,
        roleid:communityAdminRole._id,
        createdAt:new Date(),
      });

  
      res.status(201).json({
        status: true,
        content: {
          data: {
            id: community._id,
            name: community.name,
            slug: community.slug,
            owner: community.owner,
            createdAt: community.createdAt,
            updatedAt: community.updatedAt,
          },
        },
      });
    } catch (error) {
      console.error('Error creating community:', error);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  });

  //endpoint to get all communities
app.get('/v1/community',authenticateToken, async (req, res) => {
    try {

      //authentication middleware adds user information to req.user
      const userId = req.user._id;

      const page = req.query.page ? parseInt(req.query.page) : 1;
      const perPage = 10;
  
      if (page < 1) {
        return res.status(400).json({ error: 'Invalid page number' });
      }
  
      // Calculating the skip value for pagination
      const skip = (page - 1) * perPage;
  
      // Fetching communities with pagination
      const communities = await Communitycollection.find()
        .skip(skip)
        .limit(perPage);
  
      const totalCommunities = await Communitycollection.countDocuments();
  
      // Validating if the requested page is within the available range
      if (skip >= totalCommunities && totalCommunities > 0) {
        return res.status(404).json({ error: 'Page not found' });
      }

      const communitiesWithOwners = await Promise.all(
        communities.map(async (community) => {
          const owner = await collection.findById(community.owner).select('name');
          return {
            id: community._id,
            name: community.name,
            slug: community.slug,
            owner: {
              id: owner._id,
              name: owner.name,
            },
            created_at: community.createdAt,
            updated_at: community.updatedAt,
          };
        })
      );

      // Calculating total pages
      const totalPages = Math.ceil(totalCommunities / perPage);

      const responseData = {
        status: true,
        content: {
          meta: {
            total: totalCommunities,
            pages: totalPages,
            page: page,
          },
          data: communitiesWithOwners,
        },
      };
  
      res.status(200).json(responseData);
    } catch (error) {
      console.error('Error fetching communities:', error);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  });

// Endpoint to get all members of a community with pagination
app.get('/v1/community/:id/members', authenticateToken, async (req, res) => {
  try {
    // Assuming your authentication middleware adds user information to req.user
    const userId = req.user._id;
    
    // Community ID from the request params
    const communityId = req.params.id;

    // Pagination parameters (adjust as needed)
    const page = parseInt(req.query.page) || 1;
    const pageSize = 10;

    // Fetch total count of members in the community
    const totalMembersCount = await Membercollection.countDocuments({ communityid: communityId });

    if (totalMembersCount === 0) {
      return res.status(200).json({
        status: true,
        content: {
          meta: {
            total: 0,
            pages: 0,
            page: page,
          },
          data: [],
        },
      });
    }

    // Calculate total number of pages
    const totalPages = Math.ceil(totalMembersCount / pageSize);

    // Check if the requested page is valid
    if (page > totalPages || page < 1) {
      return res.status(400).json({ error: 'Invalid page number' });
    }

    // Fetch members with pagination
    const members = await Membercollection.find({ communityid: communityId })
      .skip((page - 1) * pageSize)
      .limit(pageSize)
      //this can be a better approach if types of userid and role id is allowed to be object type but as in assignment they are mentioned as string types
      // .populate('userid', 'name') // Populate user details with only 'name' field 
      // .populate('roleid', 'name'); // Populate role details with only 'name' field

    // Format the response in the specified format
    const response = {
      status: true,
      content: {
        meta: {
          total: totalMembersCount,
          pages: totalPages,
          page: page,
        },
        data: members.map(async member => ({
          id: member._id,  
          community: member.communityid,
          user: {
            id: member.userid,
            name: await collection.findById(member.userid).select('name'),
          },
          role: {
            id: member.roleid,
            name: await Rolecollection.findById(member.roleid).select('name'),
          },
          created_at: member.createdAt,
        })),
      },
    };

    return res.status(200).json(response);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Endpoint to get communities owned by the currently signed-in user with pagination
app.get('/v1/community/me/owner', authenticateToken, async (req, res) => {
  try {
    // authentication middleware adds user information to req.user
    const userId = req.user._id;

    // Pagination parameters (adjust as needed)
    const page = parseInt(req.query.page) || 1;
    const pageSize = 10;

    // Fetch total count of communities owned by the user
    const totalCommunitiesCount = await Communitycollection.countDocuments({ owner: userId });

    if (totalCommunitiesCount === 0) {
      return res.status(200).json({
        status: true,
        content: {
          meta: {
            total: 0,
            pages: 0,
            page: page,
          },
          data: [],
        },
      });
    }

    // Calculate total number of pages
    const totalPages = Math.ceil(totalCommunitiesCount / pageSize);

    // Check if the requested page is valid
    if (page > totalPages || page < 1) {
      return res.status(400).json({ error: 'Invalid page number' });
    }

    // Fetch communities owned by the user with pagination
    const communities = await Communitycollection.find({ owner: userId })
      .skip((page - 1) * pageSize)
      .limit(pageSize);

    // Format the response in the specified format
    const response = {
      status: true,
      content: {
        meta: {
          total: totalCommunitiesCount,
          pages: totalPages,
          page: page,
        },
        data: communities.map(community => ({
          id: community._id, 
          name: community.name,
          slug: community.slug,
          owner: community.owner,
          created_at: community.createdAt,
          updated_at: community.updatedAt,
        })),
      },
    };

    return res.status(200).json(response);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

//endpoint to see communities joined by me
app.get('/v1/community/me/member', authenticateToken, async (req, res) => {
  try {
    // Assuming your authentication middleware adds user information to req.user
    const userId = req.user._id;

    // Fetch the roleid for "community member" from the Rolecollection (case-insensitive)
    let communityMemberRole = await Rolecollection.findOne({ name: { $regex: /^community member$/i } }).select('_id');

    // If "community member" role doesn't exist, create it
    if (!communityMemberRole) {
      const newCommunityMemberRole = await Rolecollection.create({
        name: 'community member',
      });
      communityMemberRole = newCommunityMemberRole;
    }

    // Pagination parameters (adjust as needed)
    const page = parseInt(req.query.page) || 1;
    const pageSize = 10;

    // Fetch total count of communities where the user is a member
    const totalCommunitiesCount = await Membercollection.countDocuments({
      userid: userId,
      roleid: communityMemberRole._id,
    });

    if (totalCommunitiesCount === 0) {
      return res.status(200).json({
        status: true,
        content: {
          meta: {
            total: 0,
            pages: 0,
            page: page,
          },
          data: [],
        },
      });
    }

    // Calculate total number of pages
    const totalPages = Math.ceil(totalCommunitiesCount / pageSize);

    // Check if the requested page is valid
    if (page > totalPages || page < 1) {
      return res.status(400).json({ error: 'Invalid page number' });
    }

    // Fetch communities with pagination
    const memberCommunities = await Membercollection.find({
      userid: userId,
      roleid: communityMemberRole._id,
    })
      .skip((page - 1) * pageSize)
      .limit(pageSize);
      //here populate can also be used but that is more error prone so i manually fetched by using logic below

    // fetching the required community details
    const formattedCommunities = await Promise.all(
      memberCommunities.map(async (memberCommunity) => {
        const community = await Communitycollection.findById(memberCommunity.communityid);
        const owner = await collection.findById(community.owner, 'name');
        
        return {
          id: community._id,
          name: community.name,
          slug: community.slug,
          owner: {
            id: owner._id,
            name: owner.name,
          },
          created_at: community.createdAt,
          updated_at: community.updatedAt,
        };
      })
    );

    // Format the response in the specified format
    const response = {
      status: true,
      content: {
        meta: {
          total: totalCommunitiesCount,
          pages: totalPages,
          page: page,
        },
        data: formattedCommunities,
      },
    };

    return res.status(200).json(response);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});


//Member endpoints

//endpoint to add member
app.post('/v1/member', authenticateToken, async (req, res) => {
  try {
    const { community, user, role } = req.body;

    // Check if the specified community exists
    const communityExists = await Communitycollection.exists({ _id: community });

    if (!communityExists) {
      return res.status(404).json({ error: 'Community not found' });
    }

    // Fetch the role ID for "Community Admin" from the Rolecollection
    const communityAdminRole = await Rolecollection.findOne({ name: 'Community Admin' });

    if (!communityAdminRole) {
      return res.status(500).json({ error: 'Role not found for Community Admin' });
    }

    // Check if the user making the request is a Community Admin for the specified community
    const isAdmin = await Membercollection.exists({
      communityid: community,
      userid: req.user._id,
      roleid: communityAdminRole._id,
    });

    if (!isAdmin) {
      return res.status(403).json({ error: 'NOT_ALLOWED_ACCESS' });
    }

    // Check if the member already exists
    const memberExists = await Membercollection.exists({
      communityid: community,
      userid: user,
      roleid: role,
    });

    if (memberExists) {
      return res.status(400).json({ error: 'Member already exists' });
    }

    //checking if user has a account on site or not
    const userExists = await collection.exists({ _id: user });

    if (!userExists) {
      return res.status(404).json({ error: 'User not found on site' });
    }

    // Add the member to the Membercollection
    const newMember = await Membercollection.create({
      communityid: community,
      userid: user,
      roleid: role,
      createdAt: new Date(),
    });

    res.status(201).json({
      status: true,
      content: {
        data: {
          id: newMember._id,
          community: newMember.communityid,
          user: newMember.userid,
          role: newMember.roleid,
          created_at: newMember.createdAt,
        },
      },
    });
  } catch (error) {
    console.error('Error adding member:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

//endpoint to delete member
app.delete('/v1/member/:id', authenticateToken, async (req, res) => {
  try {
    const memberId = req.params.id;

    // Check if the member exists
    const existingMember = await Membercollection.findById(memberId);

    if (!existingMember) {
      return res.status(404).json({ error: 'Member not found' });
    }

    // Fetch the role IDs for Community Admin and Community Moderator from the Rolecollection
    const adminRole = await Rolecollection.findOne({ name: 'Community Admin' });
    const moderatorRole = await Rolecollection.findOne({ name: 'Community Moderator' });

    if (!adminRole || !moderatorRole) {
      return res.status(500).json({ error: 'Roles not found for Community Admin or Moderator' });
    }

    // Check if the user making the request has the necessary permissions (Community Admin or Moderator)
    const isAdminOrModerator = await Membercollection.exists({
      _id: memberId,
      userid: req.user._id,
      roleid: { $in: [adminRole._id, moderatorRole._id] },
    });

    if (!isAdminOrModerator) {
      return res.status(403).json({ error: 'NOT_ALLOWED_ACCESS' });
    }

    // Check if the member to delete is not an admin in case of Admin role
    if (
      existingMember.roleid.equals(adminRole._id) &&
      existingMember.userid.equals(req.user._id) &&
      !isAdminOrModerator
    ) {
      return res.status(403).json({ error: 'Cannot remove yourself as Community Admin' });
    }

    // Check if the member to delete is not a moderator in case of Moderator role
    if (
      existingMember.roleid.equals(moderatorRole._id) &&
      existingMember.userid.equals(req.user._id) &&
      !isAdminOrModerator
    ) {
      return res.status(403).json({ error: 'Cannot remove yourself as Community Moderator' });
    }

    // Remove the member
    await Membercollection.findByIdAndDelete(memberId);

    res.status(200).json({ status: true });
  } catch (error) {
    console.error('Error removing member:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.listen(5000, () => {
    console.log('Server running on 5000');
});
